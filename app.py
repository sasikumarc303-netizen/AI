"""Application factory for Malware Detection Using AI."""
import os

from flask import Flask, render_template, session

from alerts.routes import alerts_bp
from auth.routes import auth_bp
from config import Config
from database import Alert, init_db
from extensions import db
from history.routes import history_bp
from main.routes import main_bp
from profile.routes import profile_bp
from reports.routes import reports_bp
from scanner.routes import scanner_bp
from usb_scanner.routes import usb_bp
from utils import generate_csrf_token


def create_app(config_object=Config) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_object)
    os.makedirs(app.config["UPLOAD_DIR"], exist_ok=True)
    os.makedirs(os.path.join(app.root_path, "instance"), exist_ok=True)

    db.init_app(app)
    init_db(app)

    # Load ML artefacts ONCE at startup (never per scan).
    from ml_engine import model as ml
    ml.load_artifacts(app.config["MODEL_DIR"], app.config["UNKNOWN_THRESHOLD"])
    if not ml.is_ready():
        app.logger.warning("ML model not ready: %s", ml.status().get("error"))

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(usb_bp)

    @app.context_processor
    def inject_globals():
        unread = 0
        if session.get("user_id"):
            unread = (Alert.query.filter_by(user_id=session["user_id"],
                                            is_read=False, is_dismissed=False)
                      .count())
        return {"csrf_token": generate_csrf_token, "unread_alerts": unread}

    @app.errorhandler(400)
    @app.errorhandler(404)
    def client_error(exc):
        return render_template("errors/error.html", code=exc.code,
                               message=exc.description or "Request could not be processed."), exc.code

    @app.errorhandler(413)
    def too_large(exc):
        return render_template("errors/error.html", code=413,
                               message="The file exceeds the maximum allowed size."), 413

    @app.errorhandler(500)
    def server_error(exc):
        # Never leak internals — log server-side, show a generic message.
        app.logger.exception("Unhandled server error")
        return render_template("errors/error.html", code=500,
                               message="An unexpected error occurred. Please try again."), 500

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
