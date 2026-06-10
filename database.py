import sqlite3
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from collections import Counter

# local sqlite db helper for alert storage and queries

# Detect Streamlit Cloud vs. local environment
if os.path.exists("/mount/src/ai-soc-analyst"):
    DB_FILE = "/tmp/soc_triage.db"
else:
    DB_FILE = str(Path(__file__).parent / "soc_triage.db")


# set up tables
def init_db():
    """create alerts table and indices if missing"""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT NOT NULL,
            source_ip       TEXT,
            dest_ip         TEXT,
            event_type      TEXT,
            severity        TEXT DEFAULT 'Medium',
            message         TEXT,
            raw_log         TEXT,          -- Full original JSON for forensic reference
            vt_result       TEXT,          -- JSON-encoded VirusTotal intelligence
            ti_result       TEXT,          -- JSON-encoded local threat intel result
            mitre_tag       TEXT,          -- MITRE ATT&CK technique string
            ai_summary      TEXT,          -- GPT-generated or fallback analysis summary
            response_plan   TEXT,          -- Recommended analyst actions
            risk_score      INTEGER DEFAULT 0,  -- Composite 0-100 risk score
            kill_chain      TEXT,          -- Cyber Kill Chain phase
            status          TEXT DEFAULT 'New',     -- Analyst workflow status
            analyst_notes   TEXT DEFAULT '',        -- Manual analyst annotations
            false_positive  INTEGER DEFAULT 0,      -- 1 if marked false positive
            created_at      TEXT DEFAULT (datetime('now'))
        )
    """)

    # Index on common query fields to improve dashboard performance
    cur.execute("CREATE INDEX IF NOT EXISTS idx_severity ON alerts(severity)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_status ON alerts(status)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_event_type ON alerts(event_type)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_risk_score ON alerts(risk_score DESC)")

    conn.commit()
    conn.close()


# save raw alerts
def insert_alert(alert_dict: dict) -> int:
    """parse and save raw alert, returns database row id"""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO alerts
            (timestamp, source_ip, dest_ip, event_type, severity, message, raw_log)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        alert_dict.get("timestamp") or datetime.utcnow().isoformat(),
        alert_dict.get("source_ip") or alert_dict.get("src_ip"),
        alert_dict.get("dest_ip")   or alert_dict.get("destination"),
        alert_dict.get("event_type") or alert_dict.get("type"),
        alert_dict.get("severity", "Medium"),
        alert_dict.get("message")  or alert_dict.get("msg"),
        json.dumps(alert_dict),         # Always preserve the original event in full
    ))

    row_id = cur.lastrowid
    conn.commit()
    conn.close()
    return row_id


# update columns
def update_alert(row_id: int, fields: dict):
    """update matching fields for an alert ID"""
    if not fields:
        return

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    set_clause = ", ".join(f"{col} = ?" for col in fields)
    values = list(fields.values()) + [row_id]
    cur.execute(f"UPDATE alerts SET {set_clause} WHERE id = ?", values)
    conn.commit()
    conn.close()


def update_alert_status(row_id: int, status: str, notes: str = ""):
    """change alert status and add notes"""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(
        "UPDATE alerts SET status = ?, analyst_notes = ? WHERE id = ?",
        (status, notes, row_id)
    )
    conn.commit()
    conn.close()


def mark_false_positive(row_id: int):
    """mark alert as false positive"""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(
        "UPDATE alerts SET false_positive = 1, status = 'False Positive' WHERE id = ?",
        (row_id,)
    )
    conn.commit()
    conn.close()


# fetch functions
def get_all_alerts() -> list[dict]:
    """get all alerts sorted by risk score"""
    return _query("SELECT * FROM alerts ORDER BY risk_score DESC, id DESC")


def get_alert_by_id(row_id: int) -> dict | None:
    """
    Retrieves a single alert by its primary key.

    Args:
        row_id : The alert ID to look up.

    Returns:
        Alert dictionary or None if not found.
    """
    results = _query("SELECT * FROM alerts WHERE id = ?", (row_id,))
    return results[0] if results else None


def get_alerts_by_severity(severity: str) -> list[dict]:
    """
    Filters alerts by severity level.

    Args:
        severity : One of 'Critical', 'High', 'Medium', 'Low'.

    Returns:
        List of matching alert dictionaries.
    """
    return _query(
        "SELECT * FROM alerts WHERE severity = ? ORDER BY risk_score DESC",
        (severity,)
    )


def get_alerts_by_status(status: str) -> list[dict]:
    """
    Filters alerts by analyst workflow status.

    Args:
        status : One of 'New', 'In Review', 'Escalated', 'Resolved', 'False Positive'.

    Returns:
        List of matching alert dictionaries.
    """
    return _query(
        "SELECT * FROM alerts WHERE status = ? ORDER BY risk_score DESC",
        (status,)
    )


def get_alerts_by_event_type(event_type: str) -> list[dict]:
    """
    Filters alerts by event type keyword (partial match).

    Args:
        event_type : Event type keyword to search for.

    Returns:
        List of matching alert dictionaries.
    """
    return _query(
        "SELECT * FROM alerts WHERE event_type LIKE ? ORDER BY risk_score DESC",
        (f"%{event_type}%",)
    )


def get_high_risk_alerts(min_score: int = 60) -> list[dict]:
    """
    Returns all alerts with a risk score above a specified threshold.
    Default threshold is 60 (out of 100), which maps to High priority.

    Args:
        min_score : Minimum risk score to include. Default: 60.

    Returns:
        List of high-risk alert dictionaries.
    """
    return _query(
        "SELECT * FROM alerts WHERE risk_score >= ? ORDER BY risk_score DESC",
        (min_score,)
    )


def get_malicious_alerts() -> list[dict]:
    """
    Returns all alerts where VirusTotal flagged the source IP as malicious.

    Returns:
        List of malicious-flagged alert dictionaries.
    """
    return _query(
        "SELECT * FROM alerts WHERE vt_result LIKE '%Malicious%' ORDER BY risk_score DESC"
    )


def get_recent_alerts(hours: int = 24) -> list[dict]:
    """
    Returns alerts created within the last N hours.
    Useful for shift briefings and real-time monitoring views.

    Args:
        hours : Look-back window in hours. Default: 24.

    Returns:
        List of alert dictionaries within the time window.
    """
    cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
    return _query(
        "SELECT * FROM alerts WHERE created_at >= ? ORDER BY risk_score DESC",
        (cutoff,)
    )


# kpi metrics helper
def get_statistics() -> dict:
    """calculate kpi numbers for dashboard cards"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        cur.execute("SELECT * FROM alerts")
        rows = [dict(r) for r in cur.fetchall()]
    except sqlite3.OperationalError:
        rows = []
    finally:
        conn.close()

    if not rows:
        return {
            "total": 0, "by_severity": {}, "by_status": {}, "by_event_type": {},
            "avg_risk_score": 0, "malicious_pct": 0, "false_positive_count": 0
        }

    total = len(rows)
    by_severity    = dict(Counter(r.get("severity", "Unknown") for r in rows))
    by_status      = dict(Counter(r.get("status", "New") for r in rows))
    by_event_type  = dict(Counter(r.get("event_type", "Unknown") for r in rows).most_common(10))
    avg_risk       = round(sum(r.get("risk_score", 0) or 0 for r in rows) / total, 1)
    fp_count       = sum(1 for r in rows if r.get("false_positive") == 1)

    malicious_count = 0
    for r in rows:
        try:
            vt = json.loads(r.get("vt_result") or "{}")
            if vt.get("verdict") == "Malicious":
                malicious_count += 1
        except (json.JSONDecodeError, TypeError):
            pass

    return {
        "total": total,
        "by_severity": by_severity,
        "by_status": by_status,
        "by_event_type": by_event_type,
        "avg_risk_score": avg_risk,
        "malicious_pct": round((malicious_count / total) * 100, 1) if total > 0 else 0,
        "false_positive_count": fp_count,
    }


def get_top_source_ips(limit: int = 10) -> list[dict]:
    """
    Returns the top N most frequently appearing source IPs.
    Used in the threat intelligence and analytics views.

    Args:
        limit : Number of results to return. Default: 10.

    Returns:
        List of dicts with keys: ip, count, risk (from most recent alert).
    """
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT source_ip, COUNT(*) as alert_count, MAX(risk_score) as peak_risk
            FROM alerts
            WHERE source_ip IS NOT NULL AND source_ip != ''
            GROUP BY source_ip
            ORDER BY alert_count DESC
            LIMIT ?
        """, (limit,))
        rows = cur.fetchall()
    except sqlite3.OperationalError:
        rows = []
    finally:
        conn.close()

    return [{"ip": r[0], "count": r[1], "peak_risk": r[2]} for r in rows]


def get_mitre_frequency() -> dict:
    """
    Returns a frequency count of all MITRE ATT&CK techniques observed.
    Used to build the threat landscape visualization.

    Returns:
        Dictionary of technique → count (sorted by frequency).
    """
    rows = _query("SELECT mitre_tag FROM alerts WHERE mitre_tag IS NOT NULL")
    technique_counts = Counter()
    for row in rows:
        tag = row.get("mitre_tag", "")
        primary = tag.split("\n")[0].split("|")[0].strip()  # Get main technique only
        if primary:
            technique_counts[primary] += 1
    return dict(technique_counts.most_common(15))


# ===================================================================
# -- MAINTENANCE
# ===================================================================

def clear_all_alerts():
    """
    Deletes all records from the alerts table.
    WARNING: This is a destructive, irreversible operation.
    Use only for demo resets and testing environments.
    """
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()


def export_alerts_csv() -> str:
    """format all alerts as CSV string for download"""
    rows = get_all_alerts()
    if not rows:
        return "No alerts to export."

    headers = [
        "id", "timestamp", "source_ip", "dest_ip", "event_type",
        "severity", "risk_score", "status", "mitre_tag", "kill_chain",
        "message", "analyst_notes"
    ]

    lines = [",".join(headers)]
    for r in rows:
        values = []
        for h in headers:
            val = str(r.get(h) or "").replace(",", ";").replace("\n", " ")
            values.append(f'"{val}"')
        lines.append(",".join(values))

    return "\n".join(lines)


# ===================================================================
# -- INTERNAL HELPERS
# ===================================================================

def _query(sql: str, params: tuple = ()) -> list[dict]:
    """run select query and return rows as dicts"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    try:
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()
