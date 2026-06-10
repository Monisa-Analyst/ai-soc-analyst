import os
import json
import logging
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------
# AUDIT LOGGING MODULE
# Maintains a persistent, structured audit trail of every
# action taken by the SOC triage system. This log is
# essential for compliance and post-incident forensics.
# ---------------------------------------------------------

# Log file is stored alongside the database
LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / "soc_audit.log"
PIPELINE_LOG = LOG_DIR / "pipeline_events.jsonl"  # Machine-readable JSONL format

# --- Configure Python's built-in logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)s]  %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()  # Also prints to console/terminal
    ]
)

_logger = logging.getLogger("SOC_TRIAGE")


def log_ingestion(alert_id: int, source: str, event_type: str, severity: str):
    """
    Records when a new alert is ingested into the system.

    Args:
        alert_id   : Database row ID assigned to this alert.
        source     : Where the log came from (e.g., 'CSV Upload', 'Manual Entry').
        event_type : The type of security event detected.
        severity   : The severity level of the event.
    """
    msg = (
        f"INGEST  | ID={alert_id:<6} | Source='{source}' | "
        f"Type='{event_type}' | Severity='{severity}'"
    )
    _logger.info(msg)
    _append_jsonl({
        "action": "INGEST",
        "alert_id": alert_id,
        "source": source,
        "event_type": event_type,
        "severity": severity,
        "timestamp": _now()
    })


def log_enrichment(alert_id: int, ip: str, verdict: str, detections: str):
    """
    Records the result of a VirusTotal IP enrichment lookup.

    Args:
        alert_id   : The alert being enriched.
        ip         : The IP address that was looked up.
        verdict    : VT verdict — 'Malicious' or 'Clean'.
        detections : Number of AV engines that flagged the IP.
    """
    msg = (
        f"ENRICH  | ID={alert_id:<6} | IP='{ip}' | "
        f"Verdict='{verdict}' | Detections='{detections}'"
    )
    _logger.info(msg)
    _append_jsonl({
        "action": "ENRICH",
        "alert_id": alert_id,
        "ip": ip,
        "verdict": verdict,
        "detections": detections,
        "timestamp": _now()
    })


def log_analysis(alert_id: int, mitre_tag: str, risk_score: int):
    """
    Records the AI analysis results for an alert.

    Args:
        alert_id   : The alert that was analyzed.
        mitre_tag  : The MITRE ATT&CK technique that was matched.
        risk_score : Computed risk score (0–100).
    """
    msg = (
        f"ANALYZE | ID={alert_id:<6} | MITRE='{mitre_tag}' | "
        f"Risk Score={risk_score}/100"
    )
    _logger.info(msg)
    _append_jsonl({
        "action": "ANALYZE",
        "alert_id": alert_id,
        "mitre_tag": mitre_tag,
        "risk_score": risk_score,
        "timestamp": _now()
    })


def log_status_change(alert_id: int, old_status: str, new_status: str, analyst: str = "system"):
    """
    Records a manual status change by an analyst (e.g., 'New' -> 'In Review').

    Args:
        alert_id   : The alert whose status changed.
        old_status : Previous status string.
        new_status : New status string.
        analyst    : The user or process that made the change.
    """
    msg = (
        f"STATUS  | ID={alert_id:<6} | '{old_status}' → '{new_status}' | "
        f"Analyst='{analyst}'"
    )
    _logger.info(msg)
    _append_jsonl({
        "action": "STATUS_CHANGE",
        "alert_id": alert_id,
        "old_status": old_status,
        "new_status": new_status,
        "analyst": analyst,
        "timestamp": _now()
    })


def log_error(context: str, error: Exception):
    """
    Records any unexpected errors encountered during pipeline execution.

    Args:
        context : Human-readable description of what was happening.
        error   : The Python exception object.
    """
    _logger.error(f"ERROR   | Context='{context}' | {type(error).__name__}: {error}")
    _append_jsonl({
        "action": "ERROR",
        "context": context,
        "error_type": type(error).__name__,
        "error_msg": str(error),
        "timestamp": _now()
    })


def log_report_generated(report_path: str, alert_count: int):
    """Records when a report is exported by the system."""
    _logger.info(f"REPORT  | Exported {alert_count} alerts → {report_path}")
    _append_jsonl({
        "action": "REPORT",
        "path": report_path,
        "alert_count": alert_count,
        "timestamp": _now()
    })


def get_recent_logs(n: int = 50) -> list[str]:
    """
    Returns the last N lines from the main audit log file.
    Used by the Streamlit Settings/Logs tab to display recent activity.

    Args:
        n : Number of log lines to return. Default is 50.

    Returns:
        A list of stripped log line strings.
    """
    if not LOG_FILE.exists():
        return ["No log entries yet."]
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()
    return [line.strip() for line in lines[-n:] if line.strip()]


def get_pipeline_events(n: int = 100) -> list[dict]:
    """
    Returns the last N structured pipeline events from the JSONL log.
    Useful for analytics dashboards or compliance reports.

    Args:
        n : Number of events to return. Default is 100.

    Returns:
        A list of event dictionaries.
    """
    if not PIPELINE_LOG.exists():
        return []
    with open(PIPELINE_LOG, "r", encoding="utf-8") as f:
        lines = f.readlines()
    events = []
    for line in lines[-n:]:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


# --- Internal Helper Functions ---

def _now() -> str:
    """Returns ISO 8601 formatted timestamp for log entries."""
    return datetime.utcnow().isoformat() + "Z"


def _append_jsonl(record: dict):
    """Appends a JSON record to the machine-readable JSONL pipeline log."""
    with open(PIPELINE_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
