"""Create synthetic demo accounts, one sample document, and a viewer grant.
Run once for a local demo: python scripts/seed_demo.py
Never deploy the published demo passwords to a public environment.
"""
import hashlib
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app import app, db, User, Document, Permission  # noqa: E402

ACCOUNTS = [
    ("Demo Admin", "admin@trustvault.local", "DemoAdminPassword!2026", "admin"),
    ("Demo Owner", "owner@trustvault.local", "DemoOwnerPassword!2026", "owner"),
    ("Demo Viewer", "viewer@trustvault.local", "DemoViewerPassword!2026", "viewer"),
]

with app.app_context():
    users = {}
    for name, email, password, role in ACCOUNTS:
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(full_name=name, email=email, role=role)
            user.set_password(password)
            db.session.add(user)
        else:
            # Keep local seed credentials predictable for a disposable local demo.
            user.full_name = name
            user.role = role
            user.is_active_account = True
            user.set_password(password)
        users[role] = user
    db.session.commit()

    sample = Document.query.filter_by(owner_id=users["owner"].id,
                                      title="Sample Confidential Contract",
                                      deleted_at=None).first()
    if not sample:
        content = (
            "TRUSTVAULT SYNTHETIC DEMO FILE\n"
            "This fictional contract contains no real personal or confidential data.\n"
            "Use it to demonstrate document-level Read access and revocation.\n"
        ).encode("utf-8")
        storage_key = secrets.token_hex(24)
        storage_dir = Path(app.config["PRIVATE_STORAGE"])
        storage_dir.mkdir(parents=True, exist_ok=True)
        (storage_dir / storage_key).write_bytes(content)
        sample = Document(
            owner_id=users["owner"].id,
            title="Sample Confidential Contract",
            category="Contract",
            original_filename="sample-contract.txt",
            storage_key=storage_key,
            mime_type="text/plain",
            size_bytes=len(content),
            sha256_hash=hashlib.sha256(content).hexdigest(),
        )
        db.session.add(sample)
        db.session.commit()

    grant = Permission.query.filter_by(document_id=sample.id,
                                       user_id=users["viewer"].id,
                                       revoked_at=None).first()
    if not grant:
        db.session.add(Permission(document_id=sample.id,
                                  user_id=users["viewer"].id,
                                  level="read",
                                  granted_by=users["owner"].id))
        db.session.commit()

    print("Synthetic demo accounts and sample document are ready.")
    for _, email, password, role in ACCOUNTS:
        print(f"{role}: {email} / {password}")
    print("Sample document: Sample Confidential Contract (owner + viewer Read grant)")
