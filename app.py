import os
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
import hashlib
import secrets

from flask import Flask, abort, current_app, flash, jsonify, redirect, render_template, request, send_file, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import text
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from config import Config

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

ALLOWED_EXTENSIONS = {"pdf", "txt", "png", "jpg", "jpeg", "docx", "xlsx", "csv"}
MAX_FILE_SIZE = 10 * 1024 * 1024


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="viewer")
    is_active_account = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    @property
    def is_active(self):
        return self.is_active_account

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(80), nullable=False, default="General")
    original_filename = db.Column(db.String(255), nullable=False)
    storage_key = db.Column(db.String(80), unique=True, nullable=False)
    mime_type = db.Column(db.String(120), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False)
    sha256_hash = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = db.Column(db.DateTime, nullable=True)
    owner = db.relationship("User", foreign_keys=[owner_id])


class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey("document.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    level = db.Column(db.String(10), nullable=False)
    granted_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    revoked_at = db.Column(db.DateTime, nullable=True)
    recipient = db.relationship("User", foreign_keys=[user_id])
    __table_args__ = (
        db.UniqueConstraint("document_id", "user_id", "revoked_at", name="uq_document_user_revocation"),
        # NULL values do not collide in many SQL engines. This partial index
        # guarantees one active grant per user/document on SQLite and PostgreSQL.
        db.Index(
            "uq_active_permission_document_user",
            "document_id", "user_id", unique=True,
            sqlite_where=text("revoked_at IS NULL"),
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    document_id = db.Column(db.Integer, nullable=True, index=True)
    action = db.Column(db.String(40), nullable=False, index=True)
    outcome = db.Column(db.String(20), nullable=False)
    details = db.Column(db.String(500), nullable=False, default="")
    request_id = db.Column(db.String(64), nullable=False, default=lambda: secrets.token_hex(16))
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    previous_hash = db.Column(db.String(64), nullable=False, default="GENESIS")
    event_hash = db.Column(db.String(64), nullable=False, default="")


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None


def _audit_hash(entry):
    """Hash canonical event fields; SQLite may return UTC timestamps as naive."""
    stamp = entry.timestamp
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    else:
        stamp = stamp.astimezone(timezone.utc)
    payload = "|".join([
        str(entry.actor_id), str(entry.document_id), entry.action, entry.outcome,
        entry.details, stamp.isoformat(), entry.previous_hash, entry.request_id,
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_audit_chain():
    """Return (valid, checked_count); useful for detecting edits, not preventing them."""
    expected_previous = "GENESIS"
    entries = AuditLog.query.order_by(AuditLog.id.asc()).all()
    for entry in entries:
        if entry.previous_hash != expected_previous or entry.event_hash != _audit_hash(entry):
            return False, len(entries)
        expected_previous = entry.event_hash
    return True, len(entries)


def audit(action, outcome, document_id=None, details=""):
    """Append an application audit event with explicitly initialized fields."""
    previous = db.session.query(AuditLog).order_by(AuditLog.id.desc()).first()
    previous_hash = previous.event_hash if previous and previous.event_hash else "GENESIS"
    entry = AuditLog(
        actor_id=current_user.id if current_user.is_authenticated else None,
        document_id=document_id,
        action=action,
        outcome=outcome,
        details=(details or "")[:500],
        timestamp=datetime.now(timezone.utc),
        request_id=secrets.token_hex(16),
        previous_hash=previous_hash,
    )
    entry.event_hash = _audit_hash(entry)
    db.session.add(entry)
    db.session.commit()


def active_permission(user_id, document_id):
    return Permission.query.filter_by(
        user_id=user_id, document_id=document_id, revoked_at=None
    ).order_by(Permission.id.desc()).first()


def can_access(user, document, action="read"):
    if not user or not user.is_authenticated or not user.is_active:
        return False
    if document.deleted_at is not None:
        return False
    # Admin access is intentionally limited: admins can inspect audit metadata,
    # but do not automatically read document contents.
    if document.owner_id == user.id:
        return action in {"read", "edit", "delete", "share"}
    # Editors may change document metadata, but only the owner may delete or share.
    if action in {"delete", "share"}:
        return False
    grant = active_permission(user.id, document.id)
    if not grant:
        return False
    if action == "read":
        return grant.level in {"read", "edit"}
    if action == "edit":
        return grant.level == "edit"
    return False


def require_document_access(action="read"):
    def decorator(view):
        @wraps(view)
        def wrapped(document_id, *args, **kwargs):
            document = db.session.get(Document, document_id)
            if not document or document.deleted_at is not None:
                audit("DOCUMENT_ACCESS", "DENIED", document_id, "Document not found or unavailable")
                abort(404)
            if not can_access(current_user, document, action):
                audit("DOCUMENT_ACCESS", "DENIED", document_id, f"Action denied: {action}")
                abort(403)
            return view(document, *args, **kwargs)
        return wrapped
    return decorator


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE + 1024 * 1024
    Path(app.config["PRIVATE_STORAGE"]).mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "login"
    login_manager.login_message = "Please log in to continue."
    csrf.init_app(app)

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            # Public registration can create owners/viewers only, never admins.
            role = request.form.get("role", "viewer")
            if role not in {"owner", "viewer"}:
                role = "viewer"
            if not name or len(name) > 120 or "@" not in email or len(password) < 10:
                flash("Enter a name, valid email, and password of at least 10 characters.", "error")
                return render_template("register.html")
            if User.query.filter_by(email=email).first():
                flash("An account with that email already exists.", "error")
                return render_template("register.html")
            user = User(full_name=name, email=email, role=role)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            audit("REGISTER", "SUCCESS", details=f"Created account role={role}")
            flash("Account created. You can now log in.", "success")
            return redirect(url_for("login"))
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            user = User.query.filter_by(email=email).first()
            if user and user.is_active and user.check_password(password):
                login_user(user, fresh=True)
                audit("LOGIN", "SUCCESS", details="User login")
                return redirect(url_for("dashboard"))
            audit("LOGIN", "DENIED", details="Invalid credentials or inactive account")
            flash("Invalid email or password.", "error")
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        audit("LOGOUT", "SUCCESS", details="User logout")
        logout_user()
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        owned = Document.query.filter_by(owner_id=current_user.id, deleted_at=None).all()
        granted_ids = [
            p.document_id for p in Permission.query.filter_by(user_id=current_user.id, revoked_at=None).all()
        ]
        shared = Document.query.filter(Document.id.in_(granted_ids), Document.deleted_at.is_(None)).all() if granted_ids else []
        docs = {d.id: d for d in owned + shared}
        return render_template("dashboard.html", documents=list(docs.values()))

    @app.route("/documents/upload", methods=["GET", "POST"])
    @login_required
    def upload_document():
        if current_user.role not in {"owner", "admin"}:
            abort(403)
        if request.method == "POST":
            file = request.files.get("file")
            title = request.form.get("title", "").strip()
            category = request.form.get("category", "General").strip()[:80] or "General"
            if not file or not file.filename or not title:
                flash("Choose a file and enter a title.", "error")
                return render_template("upload.html")
            original = secure_filename(file.filename)
            if not original or not allowed_file(original):
                flash("Unsupported file type.", "error")
                return render_template("upload.html")
            content = file.read(MAX_FILE_SIZE + 1)
            if not content or len(content) > MAX_FILE_SIZE:
                flash("File is empty or exceeds the 10 MB limit.", "error")
                return render_template("upload.html")
            # Minimal signature validation for common formats; not malware scanning.
            ext = original.rsplit(".", 1)[1].lower()
            signatures = {"pdf": content.startswith(b"%PDF-"), "png": content.startswith(b"\x89PNG\r\n\x1a\n"),
                          "jpg": content.startswith(b"\xff\xd8\xff")}
            if ext in signatures and not signatures[ext]:
                flash("File content does not match its extension.", "error")
                return render_template("upload.html")
            storage_key = secrets.token_hex(24)
            storage_path = Path(current_app.config["PRIVATE_STORAGE"]) / storage_key
            storage_path.write_bytes(content)
            doc = Document(
                owner_id=current_user.id, title=title[:255], category=category,
                original_filename=original[:255], storage_key=storage_key,
                mime_type=file.mimetype or "application/octet-stream", size_bytes=len(content),
                sha256_hash=hashlib.sha256(content).hexdigest()
            )
            db.session.add(doc)
            db.session.commit()
            audit("UPLOAD", "SUCCESS", doc.id, f"Uploaded file size={len(content)}")
            flash("Document uploaded securely.", "success")
            return redirect(url_for("dashboard"))
        return render_template("upload.html")

    @app.route("/documents/<int:document_id>")
    @login_required
    @require_document_access("read")
    def document_detail(document):
        permissions = Permission.query.filter_by(document_id=document.id, revoked_at=None).all() if document.owner_id == current_user.id else []
        return render_template("document_detail.html", document=document, permissions=permissions)

    @app.route("/documents/<int:document_id>/download")
    @login_required
    @require_document_access("read")
    def download_document(document):
        path = Path(current_app.config["PRIVATE_STORAGE"]) / document.storage_key
        if not path.is_file():
            audit("DOWNLOAD", "ERROR", document.id, "Private storage object missing")
            abort(404)
        audit("DOWNLOAD", "SUCCESS", document.id, "Authorised download")
        return send_file(path, as_attachment=True, download_name=document.original_filename, mimetype="application/octet-stream")

    @app.route("/documents/<int:document_id>/edit", methods=["GET", "POST"])
    @login_required
    @require_document_access("edit")
    def edit_document(document):
        if request.method == "POST":
            title = request.form.get("title", "").strip()
            category = request.form.get("category", "General").strip()
            if not title:
                flash("Title is required.", "error")
            else:
                document.title = title[:255]
                document.category = category[:80] or "General"
                db.session.commit()
                audit("EDIT_METADATA", "SUCCESS", document.id, "Document metadata updated")
                flash("Document updated.", "success")
                return redirect(url_for("document_detail", document_id=document.id))
        return render_template("edit_document.html", document=document)

    @app.route("/documents/<int:document_id>/delete", methods=["POST"])
    @login_required
    @require_document_access("delete")
    def delete_document(document):
        document.deleted_at = datetime.now(timezone.utc)
        db.session.commit()
        audit("DELETE", "SUCCESS", document.id, "Soft-deleted document")
        flash("Document deleted.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/documents/<int:document_id>/share", methods=["GET", "POST"])
    @login_required
    @require_document_access("share")
    def share_document(document):
        if document.owner_id != current_user.id:
            abort(403)
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            level = request.form.get("level", "read")
            target = User.query.filter_by(email=email, is_active_account=True).first()
            if not target or target.id == current_user.id or level not in {"read", "edit"}:
                flash("Choose a valid active user and permission.", "error")
                return render_template("share.html", document=document)
            grant = active_permission(target.id, document.id)
            if grant:
                grant.level = level
                grant.granted_by = current_user.id
                grant.created_at = datetime.now(timezone.utc)
                db.session.commit()
                audit("PERMISSION_UPDATE", "SUCCESS", document.id, f"Updated grant for user_id={target.id} level={level}")
            else:
                grant = Permission(document_id=document.id, user_id=target.id, level=level, granted_by=current_user.id)
                db.session.add(grant)
                db.session.commit()
                audit("PERMISSION_GRANT", "SUCCESS", document.id, f"Granted {level} to user_id={target.id}")
            flash("Permission saved.", "success")
            return redirect(url_for("document_detail", document_id=document.id))
        return render_template("share.html", document=document)

    @app.route("/documents/<int:document_id>/revoke/<int:user_id>", methods=["POST"])
    @login_required
    @require_document_access("share")
    def revoke_permission(document, user_id):
        if document.owner_id != current_user.id:
            abort(403)
        grant = active_permission(user_id, document.id)
        if not grant:
            abort(404)
        grant.revoked_at = datetime.now(timezone.utc)
        db.session.commit()
        audit("PERMISSION_REVOKE", "SUCCESS", document.id, f"Revoked access from user_id={user_id}")
        flash("Access revoked.", "success")
        return redirect(url_for("document_detail", document_id=document.id))

    @app.route("/search")
    @login_required
    def search_documents():
        term = request.args.get("name", "").strip()
        category = request.args.get("category", "").strip()
        owner_email = request.args.get("owner", "").strip().lower()
        start = request.args.get("start", "").strip()
        end = request.args.get("end", "").strip()
        owned = Document.query.filter_by(owner_id=current_user.id, deleted_at=None)
        shared_ids = [p.document_id for p in Permission.query.filter_by(user_id=current_user.id, revoked_at=None).all()]
        # Search is never an administrative bypass: even admins only see documents
        # they own or have been explicitly granted. Audit metadata is a separate view.
        query = Document.query.filter(Document.deleted_at.is_(None))
        query = query.filter(db.or_(
            Document.owner_id == current_user.id,
            Document.id.in_(shared_ids) if shared_ids else db.false()
        ))
        if term:
            query = query.filter(Document.title.ilike(f"%{term}%"))
        if category:
            query = query.filter(Document.category.ilike(f"%{category}%"))
        if owner_email:
            owner = User.query.filter_by(email=owner_email).first()
            query = query.filter(Document.owner_id == owner.id) if owner else query.filter(db.false())
        try:
            if start:
                query = query.filter(Document.created_at >= datetime.fromisoformat(start))
            if end:
                query = query.filter(Document.created_at < datetime.fromisoformat(end))
        except ValueError:
            flash("Invalid date filter.", "error")
        docs = query.order_by(Document.created_at.desc()).limit(100).all()
        # Do not reveal metadata for documents that have a revoked grant.
        docs = [d for d in docs if d.owner_id == current_user.id or can_access(current_user, d, "read")]
        return render_template("search.html", documents=docs)

    @app.route("/admin/audit")
    @login_required
    def admin_audit():
        if current_user.role != "admin":
            abort(403)
        logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(500).all()
        chain_valid, chain_count = verify_audit_chain()
        return render_template("admin_audit.html", logs=logs,
                               chain_valid=chain_valid, chain_count=chain_count)

    @app.route("/admin/users", methods=["GET", "POST"])
    @login_required
    def admin_users():
        if current_user.role != "admin":
            abort(403)
        if request.method == "POST":
            user_id = request.form.get("user_id", type=int)
            active = request.form.get("active") == "true"
            target = db.session.get(User, user_id) if user_id else None
            if not target or target.id == current_user.id:
                abort(400)
            target.is_active_account = active
            db.session.commit()
            audit("ACCOUNT_STATUS", "SUCCESS", details=f"Updated user_id={target.id} active={active}")
            flash("Account status updated.", "success")
            return redirect(url_for("admin_users"))
        return render_template("admin_users.html", users=User.query.order_by(User.id).all())

    @app.errorhandler(403)
    def forbidden(error):
        return render_template("error.html", code=403, message="You are not authorised to perform this action."), 403

    @app.errorhandler(404)
    def not_found(error):
        return render_template("error.html", code=404, message="The requested resource was not found."), 404

    @app.errorhandler(413)
    def too_large(error):
        return render_template("error.html", code=413, message="The uploaded request is too large."), 413

    with app.app_context():
        db.create_all()

    return app


app = create_app()


if __name__ == "__main__":
    # Local development only. Use a production WSGI server for deployment.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
