"""Shared helpers: auth decorator, CSRF protection, safe responses."""
import functools
import hmac
import secrets

from flask import abort, redirect, request, session, url_for


def login_required(view):
    """Block unauthenticated access to protected routes."""

    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def generate_csrf_token() -> str:
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_hex(32)
        session["_csrf_token"] = token
    return token


def validate_csrf() -> None:
    """Abort 400 on a missing/invalid CSRF token for state-changing requests."""
    expected = session.get("_csrf_token", "")
    supplied = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        abort(400, description="Invalid or missing CSRF token.")


def csrf_protect(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if request.method in ("POST", "PUT", "DELETE"):
            validate_csrf()
        return view(*args, **kwargs)

    return wrapped
