"""FastAPI entry point serving the SOC dashboard UI and SIEM-ready REST API."""

from contextlib import asynccontextmanager
import json
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from app.database import (
    delete_scan,
    export_all_siem_events,
    get_scan,
    get_stats,
    init_db,
    list_scans,
    save_scan,
)
from app.models import (
    BatchScanRequest,
    BatchScanResponse,
    ScanHistoryItem,
    ScanRequest,
    ScanResponse,
    StatsResponse,
)
from app.services.headers_ssl import audit_headers_and_ssl
from app.services.phishing import evaluate_phishing_heuristics
from app.services.scoring import aggregate_scan_assessment
from app.services.threat_intel import check_threat_intel, extract_domain

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Initializes the SQLite database schema on application startup."""
    init_db()
    yield


app = FastAPI(
    title="Web & URL Security Analyzer (SIEM-Ready Edition)",
    description="Defensive security posture, TLS/headers audit, phishing heuristics & threat intel exporting SIEM JSON.",
    version="1.0.0",
    lifespan=lifespan,
)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def _run_and_persist_scan(raw_url: str) -> ScanResponse:
    """Executes all 3 security modules, aggregates risk, and persists the scan in SQLite."""
    target_url = raw_url.strip()
    if not target_url:
        raise HTTPException(status_code=422, detail="URL must not be empty")

    domain = extract_domain(target_url) or target_url
    headers_ssl = audit_headers_and_ssl(target_url)
    phishing = evaluate_phishing_heuristics(target_url)
    intel = check_threat_intel(target_url)

    assessment = aggregate_scan_assessment(
        target_url=target_url,
        domain=domain,
        headers_ssl=headers_ssl,
        phishing=phishing,
        intel=intel,
    )
    scan_id = save_scan(assessment)
    assessment["id"] = scan_id
    return ScanResponse(**assessment)


@app.get("/", include_in_schema=False)
def serve_dashboard() -> FileResponse:
    """Serves the modern single-page SOC dark dashboard."""
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health_check() -> dict[str, str]:
    """Liveness health probe for container orchestrators and monitoring."""
    return {"status": "healthy"}


@app.post("/api/scan", response_model=ScanResponse)
def scan_single_url(payload: ScanRequest) -> ScanResponse:
    """Runs HTTP/TLS, phishing heuristics, and threat intelligence checks on one URL."""
    return _run_and_persist_scan(payload.url)


@app.post("/api/scan/batch", response_model=BatchScanResponse)
def scan_batch_urls(payload: BatchScanRequest) -> BatchScanResponse:
    """Scans up to 10 URLs in one batch, persists each scan, and returns summary results."""
    cleaned_urls = [u.strip() for u in payload.urls if u.strip()]
    if not cleaned_urls:
        raise HTTPException(status_code=422, detail="At least one non-empty URL is required")
    if len(cleaned_urls) > 10:
        raise HTTPException(status_code=422, detail="A batch cannot exceed 10 URLs")

    results = [_run_and_persist_scan(u) for u in cleaned_urls]
    return BatchScanResponse(count=len(results), results=results)


@app.get("/api/history", response_model=list[ScanHistoryItem])
def get_scan_history(
    severity: Optional[str] = Query(default=None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    search: Optional[str] = Query(default=None, description="Substring search on URL or domain"),
) -> list[ScanHistoryItem]:
    """Returns saved scan summaries ordered from newest to oldest."""
    rows = list_scans(severity=severity, search=search)
    return [ScanHistoryItem(**row) for row in rows]


@app.get("/api/history/{scan_id}", response_model=ScanResponse)
def get_scan_details(scan_id: int) -> ScanResponse:
    """Returns full scan assessment details for a specific scan record."""
    record = get_scan(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found")
    return ScanResponse(**record)


@app.delete("/api/history/{scan_id}")
def delete_scan_record(scan_id: int) -> dict[str, object]:
    """Deletes a specific scan record from SQLite history."""
    deleted = delete_scan(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan record not found")
    return {"deleted": True, "id": scan_id}


@app.get("/api/stats", response_model=StatsResponse)
def get_dashboard_stats() -> StatsResponse:
    """Returns KPI metrics, severity breakdown, and most frequently missing headers."""
    return StatsResponse(**get_stats())


@app.get("/api/export/siem")
def export_siem_logs(
    format: str = Query(default="ndjson", pattern="^(ndjson|json)$"),
) -> Response:
    """Exports all persisted scan events as a downloadable SIEM NDJSON or JSON log file."""
    events = export_all_siem_events()
    if format == "json":
        content = json.dumps(events, indent=2)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="siem-security-events.json"'},
        )

    ndjson_lines = "\n".join(json.dumps(evt) for evt in events)
    return Response(
        content=ndjson_lines,
        media_type="application/x-ndjson",
        headers={"Content-Disposition": 'attachment; filename="siem-security-events.ndjson"'},
    )


@app.get("/analyze", response_model=ScanResponse)
def analyze_url_legacy(target_url: str = Query(..., description="URL to inspect")) -> ScanResponse:
    """Convenience GET alias compatible with Swagger quick testing."""
    return _run_and_persist_scan(target_url)
