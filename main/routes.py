"""Module 2 — security dashboard."""
from flask import Blueprint, render_template, session
from sqlalchemy import func

from database import Alert, ScanRecord
from ml_engine import model as ml
from utils import login_required

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
@login_required
def dashboard():
    uid = session["user_id"]
    stats = dict(
        (r.detection_result, r.c)
        for r in ScanRecord.query.with_entities(
            ScanRecord.detection_result, func.count().label("c"))
        .filter_by(user_id=uid).group_by(ScanRecord.detection_result).all())
    total = sum(stats.values())
    recent_scans = (ScanRecord.query.filter_by(user_id=uid)
                    .order_by(ScanRecord.created_at.desc()).limit(6).all())
    recent_alerts = (Alert.query.filter_by(user_id=uid, is_dismissed=False)
                     .order_by(Alert.created_at.desc()).limit(5).all())
    unread = Alert.query.filter_by(user_id=uid, is_read=False,
                                   is_dismissed=False).count()
    model_status = ml.status()
    return render_template(
        "main/dashboard.html", total=total, stats=stats,
        recent_scans=recent_scans, recent_alerts=recent_alerts,
        unread=unread, model_status=model_status,
        chart_data=[stats.get("SAFE", 0), stats.get("SUSPICIOUS", 0),
                    stats.get("MALWARE", 0), stats.get("UNKNOWN", 0),
                    stats.get("ERROR", 0)])
