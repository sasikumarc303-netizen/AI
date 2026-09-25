"""Module 8 — alert creation and lifecycle."""
import uuid

from constants import (RECOMMENDATIONS, RESULT_MALWARE, RESULT_MESSAGES,
                       RESULT_SUSPICIOUS)
from database import Alert
from extensions import db


def create_threat_alert(scan_record) -> Alert | None:
    """Create an alert for MALWARE/SUSPICIOUS results only (no alert spam)."""
    if scan_record.detection_result == RESULT_MALWARE:
        level = "CRITICAL" if (scan_record.confidence or 0) >= 0.97 else "HIGH"
    elif scan_record.detection_result == RESULT_SUSPICIOUS:
        level = "MEDIUM"
    else:
        return None
    result = scan_record.detection_result
    alert = Alert(
        alert_uuid=str(uuid.uuid4()),
        user_id=scan_record.user_id,
        scan_id=scan_record.id,
        file_name=scan_record.file_name,
        detection_type=result,
        level=level,
        message=f"{result}: {scan_record.file_name} — {RESULT_MESSAGES[result]}",
        recommended_action=RECOMMENDATIONS[result],
    )
    db.session.add(alert)
    return alert
