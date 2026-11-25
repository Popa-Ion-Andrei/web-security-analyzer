"""Offline FastAPI TestClient integration tests with SQLite persistence and mocked network calls."""

import json
from unittest.mock import patch
from fastapi.testclient import TestClient
import pytest
from app.database import init_db
from app.main import app
from app.models import HeadersSSLResult, SSLCertInfo
from app.services.headers_ssl import REQUIRED_SECURITY_HEADERS


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Configures an isolated temporary SQLite database per test."""
    db_file = tmp_path / "test_scans.db"
    monkeypatch.setenv("DATABASE_PATH", str(db_file))
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)
    init_db()
    with TestClient(app) as test_client:
        yield test_client


def _mock_audit(url: str) -> HeadersSSLResult:
    """Deterministic mock for HTTP & TLS inspections so tests run completely offline."""
    is_https = url.startswith("https://")
    if is_https:
        return HeadersSSLResult(
            https_enabled=True,
            status_code=200,
            response_time_ms=42.5,
            present_headers=["Strict-Transport-Security", "Content-Security-Policy"],
            missing_headers=["X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"],
            server_header=None,
            server_header_exposed=False,
            ssl_certificate=SSLCertInfo(valid=True, issuer="Test CA", subject="example.com", days_until_expiration=120),
        )
    return HeadersSSLResult(
        https_enabled=False,
        status_code=None,
        response_time_ms=15.0,
        present_headers=[],
        missing_headers=list(REQUIRED_SECURITY_HEADERS),
        ssl_certificate=SSLCertInfo(),
        error="Mocked connection check",
    )


def test_dashboard_and_health(client: TestClient):
    dash = client.get("/")
    assert dash.status_code == 200
    assert "Web &amp; URL Security Analyzer" in dash.text

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json() == {"status": "healthy"}


def test_scan_history_stats_export_and_delete(client: TestClient):
    with patch("app.main.audit_headers_and_ssl", side_effect=_mock_audit):
        safe_resp = client.post("/api/scan", json={"url": "https://example.com"})
        assert safe_resp.status_code == 200
        safe_data = safe_resp.json()
        assert safe_data["severity"] == "LOW"
        assert safe_data["id"] >= 1

        crit_resp = client.post("/api/scan", json={"url": "http://bad-phishing-login-verify.com/login"})
        assert crit_resp.status_code == 200
        crit_data = crit_resp.json()
        assert crit_data["severity"] == "CRITICAL"
        assert crit_data["modules"]["threat_intelligence"]["listed"] is True

    # History list and filtering
    all_hist = client.get("/api/history")
    assert all_hist.status_code == 200
    assert len(all_hist.json()) == 2

    crit_only = client.get("/api/history", params={"severity": "CRITICAL", "search": "bad-phishing"})
    assert crit_only.status_code == 200
    assert len(crit_only.json()) == 1
    assert crit_only.json()[0]["id"] == crit_data["id"]

    # Detail lookup
    detail = client.get(f"/api/history/{safe_data['id']}")
    assert detail.status_code == 200
    assert detail.json()["target_url"] == "https://example.com"

    # Stats endpoint
    stats_resp = client.get("/api/stats")
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert stats["total_scans"] == 2
    assert stats["critical_high_count"] == 1
    assert stats["clean_count"] == 1
    assert stats["severity_distribution"]["CRITICAL"] == 1
    assert stats["severity_distribution"]["LOW"] == 1
    assert len(stats["top_missing_headers"]) > 0

    # Export SIEM NDJSON
    export_resp = client.get("/api/export/siem")
    assert export_resp.status_code == 200
    lines = [json.loads(line) for line in export_resp.text.strip().splitlines()]
    assert len(lines) == 2
    assert all("event_id" in evt and "severity" in evt for evt in lines)

    # Delete record
    del_resp = client.delete(f"/api/history/{safe_data['id']}")
    assert del_resp.status_code == 200
    assert del_resp.json()["deleted"] is True

    not_found = client.get(f"/api/history/{safe_data['id']}")
    assert not_found.status_code == 404


def test_batch_scan_and_limit_validation(client: TestClient):
    with patch("app.main.audit_headers_and_ssl", side_effect=_mock_audit):
        batch_resp = client.post(
            "/api/scan/batch",
            json={
                "urls": [
                    "https://example.com",
                    "http://192.168.1.50/secure-login-verify-account-update",
                ]
            },
        )
        assert batch_resp.status_code == 200
        body = batch_resp.json()
        assert body["count"] == 2
        assert body["results"][0]["severity"] == "LOW"
        assert body["results"][1]["severity"] == "HIGH"

    too_many = client.post("/api/scan/batch", json={"urls": [f"https://example{i}.com" for i in range(11)]})
    assert too_many.status_code == 422

