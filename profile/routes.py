"""Module 11 — user profile and account settings."""
import re

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from database import ScanRecord, User
from extensions import db
from utils import csrf_protect, login_required

profile_bp = Blueprint("profile", __name__, url_prefix="/profile")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@profile_bp.route("/")
@login_required
def index():
    user = db.session.get(User, session["user_id"])
    scan_count = ScanRecord.query.filter_by(user_id=user.id).count()
    return render_template("profile/index.html", user=user, scan_count=scan_count)


@profile_bp.route("/update", methods=["POST"])
@login_required
@csrf_protect
def update():
    user = db.session.get(User, session["user_id"])
    name = (request.form.get("name") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    if not name or len(name) > 120:
        flash("Please provide a valid name (max 120 characters).", "error")
    elif not EMAIL_RE.match(email):
        flash("Please provide a valid email address.", "error")
    elif User.query.filter(User.email == email, User.id != user.id).first():
        flash("That email address is already in use.", "error")
    else:
        user.name = name
        user.email = email
        session["user_name"] = name
        db.session.commit()
        flash("Profile updated.", "success")
    return redirect(url_for("profile.index"))


@profile_bp.route("/password", methods=["POST"])
@login_required
@csrf_protect
def password():
    user = db.session.get(User, session["user_id"])
    current = request.form.get("current_password") or ""
    new = request.form.get("new_password") or ""
    confirm = request.form.get("confirm_password") or ""
    if not user.check_password(current):
        flash("Your current password is incorrect.", "error")
    elif len(new) < 8:
        flash("The new password must be at least 8 characters.", "error")
    elif new != confirm:
        flash("The new passwords do not match.", "error")
    else:
        user.set_password(new)
        db.session.commit()
        flash("Password changed successfully.", "success")
    return redirect(url_for("profile.index"))
