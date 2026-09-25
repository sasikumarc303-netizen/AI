"""Module 8 — alert list, filtering, read/dismiss."""
from flask import Blueprint, abort, redirect, render_template, request, url_for

from database import Alert
from extensions import db
from utils import csrf_protect, login_required
from flask import session

alerts_bp = Blueprint("alerts", __name__, url_prefix="/alerts")
PER_PAGE = 10


def _owned(alert_id: int) -> Alert:
    alert = db.session.get(Alert, alert_id)
    if alert is None or alert.user_id != session["user_id"]:
        abort(404)
    return alert


@alerts_bp.route("/")
@login_required
def index():
    level = request.args.get("level", "")
    state = request.args.get("state", "")
    page = max(request.args.get("page", 1, type=int), 1)
    q = Alert.query.filter_by(user_id=session["user_id"], is_dismissed=False)
    if level in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
        q = q.filter(Alert.level == level)
    if state == "unread":
        q = q.filter(Alert.is_read.is_(False))
    elif state == "read":
        q = q.filter(Alert.is_read.is_(True))
    pagination = q.order_by(Alert.created_at.desc()).paginate(
        page=page, per_page=PER_PAGE, error_out=False)
    return render_template("alerts/index.html", pagination=pagination,
                           level=level, state=state)


@alerts_bp.route("/<int:alert_id>")
@login_required
def detail(alert_id):
    alert = _owned(alert_id)
    if not alert.is_read:
        alert.is_read = True
        db.session.commit()
    return render_template("alerts/detail.html", alert=alert)


@alerts_bp.route("/<int:alert_id>/dismiss", methods=["POST"])
@login_required
@csrf_protect
def dismiss(alert_id):
    alert = _owned(alert_id)
    alert.is_dismissed = True
    db.session.commit()
    return redirect(url_for("alerts.index"))


@alerts_bp.route("/mark-all-read", methods=["POST"])
@login_required
@csrf_protect
def mark_all_read():
    Alert.query.filter_by(user_id=session["user_id"], is_read=False).update(
        {"is_read": True})
    db.session.commit()
    return redirect(url_for("alerts.index"))
