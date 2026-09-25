"""Module 9 — scan history: search, filter, sort, paginate, delete."""
import csv
import io

from flask import (Blueprint, Response, abort, redirect, render_template,
                   request, session, url_for)

from constants import DETECTION_RESULTS, RISK_LEVELS
from database import ScanRecord
from extensions import db
from utils import csrf_protect, login_required

history_bp = Blueprint("history", __name__, url_prefix="/history")
PER_PAGE = 10
SORTS = {"newest": ScanRecord.created_at.desc(), "oldest": ScanRecord.created_at.asc(),
         "name": ScanRecord.file_name.asc(), "size": ScanRecord.file_size.desc(),
         "risk": ScanRecord.risk_level.asc()}


def _query(args):
    q = ScanRecord.query.filter_by(user_id=session["user_id"])
    search = (args.get("q") or "").strip()
    if search:
        q = q.filter(ScanRecord.file_name.ilike(f"%{search}%"))
    result = args.get("result", "")
    if result in DETECTION_RESULTS:
        q = q.filter(ScanRecord.detection_result == result)
    risk = args.get("risk", "")
    if risk in RISK_LEVELS:
        q = q.filter(ScanRecord.risk_level == risk)
    sort = args.get("sort", "newest")
    q = q.order_by(SORTS.get(sort, SORTS["newest"]))
    return q, search, result, risk, sort


@history_bp.route("/")
@login_required
def index():
    page = max(request.args.get("page", 1, type=int), 1)
    q, search, result, risk, sort = _query(request.args)
    pagination = q.paginate(page=page, per_page=PER_PAGE, error_out=False)
    return render_template("history/index.html", pagination=pagination, search=search,
                           result=result, risk=risk, sort=sort,
                           results=DETECTION_RESULTS, risks=RISK_LEVELS)


@history_bp.route("/<scan_uuid>")
@login_required
def detail(scan_uuid):
    record = ScanRecord.query.filter_by(
        scan_uuid=scan_uuid, user_id=session["user_id"]).first()
    if record is None:
        abort(404)
    return render_template("history/detail.html", record=record)


@history_bp.route("/<scan_uuid>/delete", methods=["POST"])
@login_required
@csrf_protect
def delete(scan_uuid):
    record = ScanRecord.query.filter_by(
        scan_uuid=scan_uuid, user_id=session["user_id"]).first()
    if record is None:
        abort(404)
    db.session.delete(record)
    db.session.commit()
    return redirect(url_for("history.index"))


@history_bp.route("/export.csv")
@login_required
def export_csv():
    q, *_ = _query(request.args)
    rows = q.limit(5000).all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Scan ID", "File Name", "File Type", "File Size", "Scan Date",
                     "Detection Result", "Risk Level", "Confidence", "Status"])
    for r in rows:
        writer.writerow([r.scan_uuid, r.file_name, r.file_type, r.file_size,
                         r.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                         r.detection_result, r.risk_level,
                         f"{r.confidence:.2%}" if r.confidence is not None else "n/a",
                         r.status])
    return Response(buf.getvalue(), mimetype="text/csv", headers={
        "Content-Disposition": "attachment; filename=scan-history.csv"})
