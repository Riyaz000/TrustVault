import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent


def get_database_url():
    url = (
        os.environ.get("DATABASE_URL")
        or os.environ.get("MYSQL_URL")
        or ""
    ).strip()

    if url.startswith("mysql://"):
        url = url.replace("mysql://", "mysql+pymysql://", 1)

    if url.startswith("mysql+pymysql://"):
        return url

    if url.startswith("sqlite:///"):
        return url

    if not url:
        return f"sqlite:///{BASE_DIR / 'trustvault.db'}"

    return url


class Config:
    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        "change-this-secret-key"
    )

    SQLALCHEMY_DATABASE_URI = get_database_url()
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    PRIVATE_STORAGE = os.environ.get(
        "PRIVATE_STORAGE",
        str(BASE_DIR / "private_uploads")
    )

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = (
        os.environ.get("COOKIE_SECURE", "0") == "1"
    )

    WTF_CSRF_TIME_LIMIT = 3600
    WTF_CSRF_SSL_STRICT = False