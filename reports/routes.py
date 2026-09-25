"""Module 10 — report generation routes."""
from flask import Blueprint, Response, abort, render_template, session

from database import ScanRecord, User
from reports import service
from utils import login_required

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.route("/")
@login_required
def index():
    scans = (ScanRecord.query.filter_by(user_id=session["user_id"])
             .order_by(ScanRecord.created_at.desc()).limit(50).all())
    return render_template("reports/index.html", scans=scans)


@reports_bp.route("/scan/<scan_uuid>.pdf")
@login_required
def scan_pdf(scan_uuid):
    record = ScanRecord.query.filter_by(
        scan_uuid=scan_uuid, user_id=session["user_id"]).first()
    if record is None:
        abort(404)
    user = User.query.get(session["user_id"])
    pdf = service.build_scan_pdf(record, user)
    return Response(pdf, mimetype="application/pdf", headers={
        "Content-Disposition": f"attachment; filename=scan-report-{scan_uuid[:8]}.pdf"})
