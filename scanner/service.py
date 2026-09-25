"""Module 3/6 — the scan pipeline.

Flow: validate -> extract features -> predict -> classify risk ->
persist history -> alert if required -> ALWAYS remove the temp copy.
The uploaded file is never executed and is deleted after analysis.
"""
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

from flask import current_app

from alerts.service import create_threat_alert
from constants import (RECOMMENDATIONS, RESULT_ERROR, RESULT_MESSAGES,
                       RESULT_TO_RISK, RISK_UNKNOWN, STATUS_COMPLETED,
                       STATUS_FAILED)
from database import ScanRecord
from extensions import db
from ml_engine import features as fe
from ml_engine import model as ml


class ScanValidationError(Exception):
    """User-facing validation failure (size, name, etc.)."""


def validate_upload(file_storage) -> str:
    name = (file_storage.filename or "").strip()
    if not name:
        raise ScanValidationError("No file was selected.")
    if len(name) > 255:
        raise ScanValidationError("File name is too long.")
    return name


def run_scan(file_path: str, original_name: str, user_id: int,
             source: str = "upload") -> ScanRecord:
    """Execute the full pipeline for one file and persist the result."""
    started = time.time()
    detail_parts = []
    detection, risk, confidence, status = RESULT_ERROR, RISK_UNKNOWN, None, STATUS_FAILED
    sha256, file_type, size = "", "unknown", 0

    try:
        size = os.path.getsize(file_path)
        vector, meta = fe.extract_feature_vector(file_path, original_name)
        sha256 = meta["sha256"]
        file_type = meta["extension"]

        # Duplicate-submission guard: identical content scanned moments ago.
        recent = ScanRecord.query.filter(
            ScanRecord.user_id == user_id,
            ScanRecord.sha256 == sha256,
            ScanRecord.created_at > datetime.now(timezone.utc) - timedelta(seconds=10),
        ).first()
        if recent is not None and source == "upload":
            return recent

        prediction = ml.predict_features(
            vector, unknown_threshold=current_app.config["UNKNOWN_THRESHOLD"])
        detection = prediction["result"]
        risk = RESULT_TO_RISK[detection]
        confidence = prediction["confidence"]
        status = STATUS_COMPLETED
        detail_parts.append(f"Model: {prediction['model_version']}")
        detail_parts.append("Signals: " + "; ".join(meta["signals"]))
        detail_parts.append("Class probabilities: " + ", ".join(
            f"{k}={v:.2%}" for k, v in prediction["probabilities"].items()))
        if prediction["below_threshold"]:
            detail_parts.append(
                "Confidence below threshold — reported as UNKNOWN rather than guessing.")
    except ml.ModelUnavailableError as exc:
        detail_parts.append(f"Model unavailable: {exc}")
    except ml.PredictionError as exc:
        detail_parts.append(f"Prediction failed: {exc}")
    except fe.FeatureExtractionError as exc:
        detail_parts.append(f"Feature extraction failed: {exc}")
    except Exception as exc:  # never let a scan crash the app
        current_app.logger.exception("Unexpected scan failure")
        detail_parts.append(f"Unexpected error ({exc.__class__.__name__}).")

    elapsed_ms = int((time.time() - started) * 1000)
    detail_parts.append(f"Duration: {elapsed_ms} ms")

    record = ScanRecord(
        scan_uuid=str(uuid.uuid4()),
        user_id=user_id,
        file_name=original_name,
        file_type=file_type,
        file_size=size,
        sha256=sha256,
        source=source,
        detection_result=detection,
        risk_level=risk,
        confidence=confidence,
        status=status,
        detail="\n".join(detail_parts),
    )
    try:
        db.session.add(record)
        db.session.flush()
        if detection in RESULT_MESSAGES and detection in ("MALWARE", "SUSPICIOUS"):
            create_threat_alert(record)
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Failed to persist scan record")
    finally:
        if source == "upload":  # secure temp cleanup — quarantine by deletion
            try:
                os.remove(file_path)
            except OSError:
                pass
    return record


def result_view(record: ScanRecord) -> dict:
    """Assemble honest result-page content for one record."""
    return {
        "record": record,
        "message": RESULT_MESSAGES.get(record.detection_result, ""),
        "recommendation": RECOMMENDATIONS.get(record.detection_result, ""),
    }
