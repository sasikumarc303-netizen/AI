"""Module 12 — USB scanning routes."""
from flask import (Blueprint, flash, redirect, render_template, request,
                   session, url_for)

from usb_scanner import service
from utils import csrf_protect, login_required

usb_bp = Blueprint("usb", __name__, url_prefix="/usb")


@usb_bp.route("/")
@login_required
def index():
    error = None
    try:
        devices = service.list_devices()
    except Exception:
        devices, error = [], "Device enumeration is unavailable in this environment."
    return render_template("usb/index.html", devices=devices, error=error)


@usb_bp.route("/scan", methods=["POST"])
@login_required
@csrf_protect
def scan():
    device = request.form.get("device", "")
    if not device:
        flash("Please select a device to scan.", "error")
        return redirect(url_for("usb.index"))
    try:
        report = service.scan_device(device, session["user_id"])
    except service.USBAccessError as exc:
        flash(str(exc), "error")
        return redirect(url_for("usb.index"))
    except Exception:
        flash("The USB scan failed unexpectedly. No files were modified.", "error")
        return redirect(url_for("usb.index"))
    return render_template("usb/results.html", report=report)
