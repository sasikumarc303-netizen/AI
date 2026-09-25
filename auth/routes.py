"""Module 1 — secure authentication."""
import re
import time
from collections import defaultdict
from datetime import timedelta

from flask import (Blueprint, current_app, flash, redirect, render_template,
                   request, session, url_for)

from database import User
from extensions import db
from utils import csrf_protect

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 60
_attempts = defaultdict(list)  # ip -> [timestamps]; in-memory rate limiting


def _rate_limited(ip: str) -> bool:
    now = time.time()
    _attempts[ip] = [t for t in _attempts[ip] if now - t < WINDOW_SECONDS]
    return len(_attempts[ip]) >= MAX_ATTEMPTS


def _record_attempt(ip: str) -> None:
    _attempts[ip].append(time.time())


@auth_bp.route("/login", methods=["GET", "POST"])
@csrf_protect
def login():
    if session.get("user_id"):
        return redirect(url_for("main.dashboard"))
    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        if _rate_limited(ip):
            flash("Too many login attempts. Please wait a minute and try again.", "error")
            return render_template("auth/login.html"), 429
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        if not email or not password:
            flash("Email and password are required.", "error")
            return render_template("auth/login.html", email=email), 400
        user = User.query.filter_by(email=email).first()
        # Constant-shape failure message: never reveal whether the email exists.
        if user is None or not user.check_password(password):
            _record_attempt(ip)
            flash("Invalid email or password.", "error")
            return render_template("auth/login.html", email=email), 401
        session.clear()
        session.permanent = True
        current_app.permanent_session_lifetime = timedelta(
            seconds=current_app.config["PERMANENT_SESSION_LIFETIME_SECONDS"])
        session["user_id"] = user.id
        session["user_name"] = user.name
        session.pop("_csrf_token", None)  # rotate CSRF token on privilege change
        nxt = request.args.get("next", "")
        if nxt.startswith("/") and not nxt.startswith("//"):
            return redirect(nxt)
        return redirect(url_for("main.dashboard"))
    return render_template("auth/login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
@csrf_protect
def register():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        if not name or len(name) > 120:
            flash("A valid name is required.", "error")
        elif not EMAIL_RE.match(email):
            flash("A valid email address is required.", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        elif User.query.filter_by(email=email).first():
            flash("An account with this email already exists.", "error")
        else:
            user = User(name=name, email=email)
            user.set_password(password)  # hashed — never stored in plain text
            db.session.add(user)
            db.session.commit()
            flash("Account created. Please sign in.", "success")
            return redirect(url_for("auth.login"))
        return render_template("auth/register.html", name=name, email=email), 400
    return render_template("auth/register.html")


@auth_bp.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))
