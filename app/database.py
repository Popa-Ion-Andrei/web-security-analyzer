"""SQLite persistence layer for scan history, analytics, and SIEM log export."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
from typing import Any, Iterator, Optional

DEFAULT_DB_PATH = str(Path(__file__).resolve().parent.parent / "scans.db")


def get_db_path() -> str:
    """Returns the configured SQLite database file path."""
    return os.getenv("DATABASE_PATH", DEFAULT_DB_PATH)


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    """Yields a configured SQLite connection and guarantees cleanup."""
    db_path = get_db_path()
    parent = Path(db_path).parent
    if str(parent) and not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    """Creates the scans table and indexes if they do not exist."""
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                target_url TEXT NOT NULL,
                domain TEXT NOT NULL,
                overall_risk_score INTEGER NOT NULL,
                severity TEXT NOT NULL,
                missing_headers_json TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_severity ON scans(severity)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp DESC)"
        )


def save_scan(scan_payload: dict[str, Any]) -> int:
    """Persists a completed scan record and returns its assigned database ID."""
    missing_headers = scan_payload["modules"]["http_tls_audit"]["missing_headers"]
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO scans (
                timestamp,
                target_url,
                domain,
                overall_risk_score,
                severity,
                missing_headers_json,
                payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_payload["timestamp"],
                scan_payload["target_url"],
                scan_payload["domain"],
                scan_payload["overall_risk_score"],
                scan_payload["severity"],
                json.dumps(missing_headers),
                json.dumps(scan_payload),
            ),
        )
        return int(cursor.lastrowid)


def list_scans(
    severity: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Lists saved scan summaries ordered newest-first with optional filters."""
    query = (
        "SELECT id, timestamp, target_url, domain, overall_risk_score, "
        "severity, missing_headers_json FROM scans WHERE 1=1"
    )
    params: list[Any] = []

    if severity and severity.upper() != "ALL":
        query += " AND UPPER(severity) = ?"
        params.append(severity.upper())

    if search and search.strip():
        like_term = f"%{search.strip()}%"
        query += " AND (target_url LIKE ? OR domain LIKE ?)"
        params.extend([like_term, like_term])

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()

    results: list[dict[str, Any]] = []
    for row in rows:
        results.append(
            {
                "id": row["id"],
                "timestamp": row["timestamp"],
                "target_url": row["target_url"],
                "domain": row["domain"],
                "overall_risk_score": row["overall_risk_score"],
                "severity": row["severity"],
                "missing_headers": json.loads(row["missing_headers_json"]),
            }
        )
    return results


def get_scan(scan_id: int) -> Optional[dict[str, Any]]:
    """Fetches a full scan record by ID, or None if not found."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id, payload_json FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()

    if not row:
        return None

    payload = json.loads(row["payload_json"])
    payload["id"] = row["id"]
    return payload


def delete_scan(scan_id: int) -> bool:
    """Deletes a scan record by ID. Returns True if a row was removed."""
    with get_connection() as conn:
        cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cursor.rowcount > 0


def get_stats() -> dict[str, Any]:
    """Computes KPI metrics, severity distribution, and top missing headers."""
    severity_dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    header_counts: dict[str, int] = {}

    with get_connection() as conn:
        agg = conn.execute(
            """
            SELECT
                COUNT(*) AS total_scans,
                COALESCE(AVG(overall_risk_score), 0.0) AS avg_risk_score
            FROM scans
            """
        ).fetchone()
        sev_rows = conn.execute(
            "SELECT severity, COUNT(*) AS cnt FROM scans GROUP BY severity"
        ).fetchall()
        header_rows = conn.execute(
            "SELECT missing_headers_json FROM scans"
        ).fetchall()

    for row in sev_rows:
        sev = str(row["severity"]).upper()
        if sev in severity_dist:
            severity_dist[sev] = int(row["cnt"])

    for row in header_rows:
        for hdr in json.loads(row["missing_headers_json"]):
            header_counts[hdr] = header_counts.get(hdr, 0) + 1

    top_missing = [
        {"header": hdr, "count": cnt}
        for hdr, cnt in sorted(
            header_counts.items(),
            key=lambda item: (-item[1], item[0]),
        )
    ]

    total_scans = int(agg["total_scans"])
    avg_score = round(float(agg["avg_risk_score"]), 1) if total_scans > 0 else 0.0
    critical_high = severity_dist["HIGH"] + severity_dist["CRITICAL"]
    clean_count = severity_dist["LOW"]

    return {
        "total_scans": total_scans,
        "critical_high_count": critical_high,
        "clean_count": clean_count,
        "avg_risk_score": avg_score,
        "severity_distribution": severity_dist,
        "top_missing_headers": top_missing,
    }


def export_all_siem_events() -> list[dict[str, Any]]:
    """Returns SIEM-normalized JSON events for all persisted scans."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, payload_json FROM scans ORDER BY id DESC"
        ).fetchall()

    events: list[dict[str, Any]] = []
    for row in rows:
        payload = json.loads(row["payload_json"])
        if "siem_event" in payload:
            events.append(payload["siem_event"])
    return events

