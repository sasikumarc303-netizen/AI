"""Module 3 — upload UI + result page."""
import os
import uuid

from flask import (Blueprint, abort, current_app, flash, redirect,
                   render_template, request, session, url_for)
from werkzeug.utils import secure_filename

from database import ScanRecord
from scanner import service
from utils import csrf_protect, login_required

scanner_bp = Blueprint("scanner", __name__, url_prefix="/scanner")


@scanner_bp.route("/")
@login_required
def index():
    recent = (ScanRecord.query
              .filter_by(user_id=session["user_id"])
              .order_by(ScanRecord.created_at.desc()).limit(5).all())
    max_mb = current_app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
    return render_template("scanner/upload.html", recent=recent, max_mb=max_mb)


@scanner_bp.route("/upload", methods=["POST"])
@login_required
@csrf_protect
def upload():
    file = request.files.get("file")
    if file is None:
        flash("No file was provided.", "error")
        return redirect(url_for("scanner.index"))
    try:
        original_name = service.validate_upload(file)
    except service.ScanValidationError as exc:
        flash(str(exc), "error")
        return redirect(url_for("scanner.index"))

    # Secure temporary storage: random server-side name, never the client's name.
    temp_name = f"{uuid.uuid4().hex}.bin"
    temp_path = os.path.join(current_app.config["UPLOAD_DIR"], temp_name)
    try:
        file.save(temp_path)
    except OSError:
        flash("The file could not be stored for scanning. Please try again.", "error")
        return redirect(url_for("scanner.index"))

    record = service.run_scan(temp_path, original_name, session["user_id"], source="upload")
    return redirect(url_for("scanner.result", scan_uuid=record.scan_uuid))


@scanner_bp.route("/result/<scan_uuid>")
@login_required
def result(scan_uuid):
    record = ScanRecord.query.filter_by(
        scan_uuid=scan_uuid, user_id=session["user_id"]).first()
    if record is None:
        abort(404)
    return render_template("scanner/result.html", **service.result_view(record))
