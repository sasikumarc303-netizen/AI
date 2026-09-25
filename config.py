"""Application configuration. Secrets come from environment variables only."""
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")


class Config:
    # --- Core ---
    SECRET_KEY = os.environ.get("MDAI_SECRET_KEY", "dev-only-insecure-key-change-me")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "MDAI_DATABASE_URL", "sqlite:///" + os.path.join(INSTANCE_DIR, "app.db")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- Uploads / scanning ---
    UPLOAD_DIR = os.environ.get("MDAI_UPLOAD_DIR", os.path.join(INSTANCE_DIR, "uploads"))
    MAX_CONTENT_LENGTH = int(os.environ.get("MDAI_MAX_UPLOAD_MB", "50")) * 1024 * 1024
    QUARANTINE_AFTER_SCAN = True  # delete temp copy immediately after feature extraction

    # --- USB module ---
    # Only paths under this root may be scanned by the USB module (defence in depth).
    USB_ALLOWED_ROOT = os.environ.get("MDAI_USB_ROOT", "/media")
    USB_MAX_FILES = int(os.environ.get("MDAI_USB_MAX_FILES", "200"))

    # --- ML ---
    MODEL_DIR = os.path.join(BASE_DIR, "ml_engine", "artifacts")
    # Below this confidence the system returns UNKNOWN instead of guessing.
    UNKNOWN_THRESHOLD = float(os.environ.get("MDAI_UNKNOWN_THRESHOLD", "0.60"))

    # --- Session hardening ---
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME_SECONDS = int(os.environ.get("MDAI_SESSION_MINUTES", "60")) * 60

    # --- Seeded demo account (password read from env, never hard-coded in DB) ---
    SEED_ADMIN_EMAIL = os.environ.get("MDAI_ADMIN_EMAIL", "admin@example.com")
    SEED_ADMIN_PASSWORD = os.environ.get("MDAI_ADMIN_PASSWORD", "ChangeMe123!")
