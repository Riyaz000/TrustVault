import pytest
from pathlib import Path
import tempfile
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app, db, User, Document, Permission


@pytest.fixture()
def app():
    temp_dir = tempfile.TemporaryDirectory()
    app = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "PRIVATE_STORAGE": str(Path(temp_dir.name) / "files"),
        "SECRET_KEY": "test-only-secret",
    })
    with app.app_context():
        db.create_all()
        alice = User(full_name="Alice Owner", email="alice@example.test", role="owner")
        alice.set_password("AliceStrongPassword123!")
        bob = User(full_name="Bob Owner", email="bob@example.test", role="owner")
        bob.set_password("BobStrongPassword123!")
        viewer = User(full_name="Charlie Viewer", email="charlie@example.test", role="viewer")
        viewer.set_password("CharlieStrongPassword123!")
        admin = User(full_name="Dana Admin", email="dana@example.test", role="admin")
        admin.set_password("DanaStrongPassword123!")
        db.session.add_all([alice, bob, viewer, admin])
        db.session.commit()
        doc = Document(owner_id=alice.id, title="Alice confidential", category="Contract",
                       original_filename="secret.txt", storage_key="not-public-key",
                       mime_type="text/plain", size_bytes=6,
                       sha256_hash="fakehash")
        db.session.add(doc)
        db.session.commit()
        Path(app.config["PRIVATE_STORAGE"]).mkdir(parents=True, exist_ok=True)
        (Path(app.config["PRIVATE_STORAGE"]) / "not-public-key").write_text("secret", encoding="utf-8")
        app.config["TEST_DOC_ID"] = doc.id
        app.config["TEST_USERS"] = {
            "alice": alice.id, "bob": bob.id, "viewer": viewer.id, "admin": admin.id
        }
    yield app
    with app.app_context():
        db.drop_all()
    temp_dir.cleanup()


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client, email, password):
    return client.post("/login", data={"email": email, "password": password}, follow_redirects=True)
