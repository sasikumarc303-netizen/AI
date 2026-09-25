"""Shared domain constants. Single source of truth for classifications."""

# Detection results produced by the ML pipeline
RESULT_SAFE = "SAFE"
RESULT_SUSPICIOUS = "SUSPICIOUS"
RESULT_MALWARE = "MALWARE"
RESULT_UNKNOWN = "UNKNOWN"
RESULT_ERROR = "ERROR"
DETECTION_RESULTS = (RESULT_SAFE, RESULT_SUSPICIOUS, RESULT_MALWARE, RESULT_UNKNOWN, RESULT_ERROR)

# Risk levels shown to the user
RISK_NONE = "NONE"
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_CRITICAL = "CRITICAL"
RISK_UNKNOWN = "UNKNOWN"
RISK_LEVELS = (RISK_NONE, RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_CRITICAL, RISK_UNKNOWN)

# Map detection result -> risk level
RESULT_TO_RISK = {
    RESULT_SAFE: RISK_NONE,
    RESULT_SUSPICIOUS: RISK_MEDIUM,
    RESULT_MALWARE: RISK_HIGH,
    RESULT_UNKNOWN: RISK_UNKNOWN,
    RESULT_ERROR: RISK_UNKNOWN,
}

# Alert severities (module 8)
ALERT_LEVELS = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

# Honest, non-misleading wording per result (module 7 requirement)
RESULT_MESSAGES = {
    RESULT_SAFE: "No malware detected by the configured model. This is not a guarantee of safety.",
    RESULT_SUSPICIOUS: "The file shows characteristics associated with potentially unwanted or suspicious software.",
    RESULT_MALWARE: "The model classified this file as malware. Do not execute or open it.",
    RESULT_UNKNOWN: "The model could not classify this file with sufficient confidence. Requires further analysis.",
    RESULT_ERROR: "The scan could not be completed due to a processing error.",
}

RECOMMENDATIONS = {
    RESULT_SAFE: "No action required. Continue to follow standard safe-handling practices.",
    RESULT_SUSPICIOUS: "Do not execute this file. Submit it for manual review and monitor the source system.",
    RESULT_MALWARE: "Do not execute or open this file. Quarantine or remove it according to your organisation's security policy.",
    RESULT_UNKNOWN: "Treat the file as untrusted. Analyse it in an isolated sandbox environment before use.",
    RESULT_ERROR: "Retry the scan. If the problem persists, contact your security administrator.",
}

# Scan record status
STATUS_COMPLETED = "COMPLETED"
STATUS_FAILED = "FAILED"
