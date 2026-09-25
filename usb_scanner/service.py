"""Module 12 — USB device protection.

Honest-scope note: a browser/web server can only scan mounted filesystem
paths. This module scans mounted volumes under an allowed root — files are
READ ONLY, never executed, copied, or deleted. Disconnection and permission
errors are handled per-file so the scan never crashes.
"""
import os

from flask import current_app

from alerts.service import create_threat_alert
from constants import (RESULT_ERROR, RESULT_TO_RISK, STATUS_COMPLETED,
                       STATUS_FAILED)
from database import ScanRecord
from extensions import db
from ml_engine import features as fe
from ml_engine import model as ml
import uuid


class USBAccessError(Exception):
    """Device path is invalid, not mounted, or not permitted."""


def list_devices() -> list:
    """Return currently mounted, scannable volume paths."""
    root = current_app.config["USB_ALLOWED_ROOT"]
    devices = []
    for base in (root, "/mnt"):
        try:
            if os.path.isdir(base):
                for entry in sorted(os.listdir(base)):
                    path = os.path.join(base, entry)
                    if os.path.isdir(path) and os.access(path, os.R_OK):
                        devices.append(path)
        except OSError:
            continue
    return devices


def _validate_device_path(path: str) -> str:
    root = os.path.realpath(current_app.config["USB_ALLOWED_ROOT"])
    real = os.path.realpath(path)
    if not (real == root or real.startswith(root + os.sep) or real.startswith("/mnt" + os.sep)):
        raise USBAccessError("This location is outside the permitted removable-media paths.")
    if not os.path.isdir(real):
        raise USBAccessError("Device not found. It may have been disconnected.")
    return real


def scan_device(path: str, user_id: int) -> dict:
    """Scan up to USB_MAX_FILES files on the device. Never executes anything."""
    real = _validate_device_path(path)
    max_files = current_app.config["USB_MAX_FILES"]
    threshold = current_app.config["UNKNOWN_THRESHOLD"]
    results, errors, counts = [], [], {"SAFE": 0, "SUSPICIOUS": 0, "MALWARE": 0,
                                       "UNKNOWN": 0, "ERROR": 0}
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(real):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fname in filenames:
            if scanned >= max_files:
                break
            fpath = os.path.join(dirpath, fname)
            rel = os.path.relpath(fpath, real)
            try:
                vector, meta = fe.extract_feature_vector(fpath, fname)
                pred = ml.predict_features(vector, unknown_threshold=threshold)
                detection = pred["result"]
                confidence = pred["confidence"]
                status = STATUS_COMPLETED
            except ml.ModelUnavailableError as exc:
                raise USBAccessError(str(exc)) from exc
            except (fe.FeatureExtractionError, OSError, PermissionError) as exc:
                detection, confidence, status = RESULT_ERROR, None, STATUS_FAILED
                errors.append(f"{rel}: {exc if isinstance(exc, fe.FeatureExtractionError) else 'not accessible'}")
            except Exception as exc:
                detection, confidence, status = RESULT_ERROR, None, STATUS_FAILED
                errors.append(f"{rel}: unexpected error ({exc.__class__.__name__})")

            counts[detection] = counts.get(detection, 0) + 1
            record = ScanRecord(
                scan_uuid=str(uuid.uuid4()), user_id=user_id, file_name=rel,
                file_type=os.path.splitext(fname)[1] or "(none)",
                file_size=os.path.getsize(fpath) if os.path.exists(fpath) else 0,
                sha256="", source="usb", detection_result=detection,
                risk_level=RESULT_TO_RISK[detection], confidence=confidence,
                status=status, detail=f"USB scan of {real}")
            try:
                db.session.add(record)
                db.session.flush()
                if detection in ("MALWARE", "SUSPICIOUS"):
                    create_threat_alert(record)
                db.session.commit()
            except Exception:
                db.session.rollback()
            results.append({"name": rel, "result": detection,
                            "risk": RESULT_TO_RISK[detection],
                            "confidence": confidence, "scan_uuid": record.scan_uuid})
            scanned += 1
        if scanned >= max_files:
            break
    return {"device": real, "scanned": scanned, "capped": scanned >= max_files,
            "counts": counts, "results": results, "errors": errors}
