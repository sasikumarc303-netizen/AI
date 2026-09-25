"""Database models and bootstrap helpers."""
from datetime import datetime, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db


def utcnow():
    return datetime.now(timezone.utc)


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(32), nullable=False, default="analyst")
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    scans = db.relationship("ScanRecord", backref="user", lazy=True)
    alerts = db.relationship("Alert", backref="user", lazy=True)

    def set_password(self, raw_password: str) -> None:
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password_hash, raw_password)


class ScanRecord(db.Model):
    __tablename__ = "scan_records"
    id = db.Column(db.Integer, primary_key=True)
    scan_uuid = db.Column(db.String(36), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    file_name = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(120), nullable=False, default="unknown")
    file_size = db.Column(db.Integer, nullable=False, default=0)
    sha256 = db.Column(db.String(64), nullable=False, default="")
    source = db.Column(db.String(16), nullable=False, default="upload")  # upload | usb
    detection_result = db.Column(db.String(16), nullable=False, default="UNKNOWN")
    risk_level = db.Column(db.String(16), nullable=False, default="UNKNOWN")
    confidence = db.Column(db.Float, nullable=True)  # may be NULL on error
    status = db.Column(db.String(16), nullable=False, default="COMPLETED")
    detail = db.Column(db.Text, nullable=False, default="")
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)


class Alert(db.Model):
    __tablename__ = "alerts"
    id = db.Column(db.Integer, primary_key=True)
    alert_uuid = db.Column(db.String(36), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_records.id"), nullable=True)
    file_name = db.Column(db.String(255), nullable=False)
    detection_type = db.Column(db.String(32), nullable=False)
    level = db.Column(db.String(16), nullable=False, default="INFO")
    message = db.Column(db.Text, nullable=False, default="")
    recommended_action = db.Column(db.Text, nullable=False, default="")
    is_read = db.Column(db.Boolean, nullable=False, default=False)
    is_dismissed = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    scan = db.relationship("ScanRecord", backref="alerts", lazy=True)


def init_db(app) -> None:
    """Create tables and seed the initial admin account (password from env)."""
    with app.app_context():
        db.create_all()
        email = app.config["SEED_ADMIN_EMAIL"].strip().lower()
        if not User.query.filter_by(email=email).first():
            admin = User(name="Security Administrator", email=email, role="admin")
            admin.set_password(app.config["SEED_ADMIN_PASSWORD"])
            db.session.add(admin)
            db.session.commit()
