import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "local-dev-only-change-me")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'trustvault.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PRIVATE_STORAGE = os.environ.get("PRIVATE_STORAGE", str(BASE_DIR / "private_uploads"))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
    WTF_CSRF_TIME_LIMIT = 3600
