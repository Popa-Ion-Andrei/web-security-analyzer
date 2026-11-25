"""Offline unit tests for phishing heuristics, threat intelligence, headers/TLS, and scoring."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
import httpx
from app.models import HeadersSSLResult, PhishingResult, SSLCertInfo, ThreatIntelResult
from app.services.headers_ssl import REQUIRED_SECURITY_HEADERS, audit_headers_and_ssl
from app.services.phishing import evaluate_phishing_heuristics
from app.services.scoring import aggregate_scan_assessment, classify_severity
from app.services.threat_intel import check_threat_intel


def test_phishing_clean_url():
    result = evaluate_phishing_heuristics("https://example.com")
    assert result.phishing_probability == 0.0
    assert result.triggered_rules == []


def test_phishing_all_rules_triggered():
    long_url = (
        "http://user@xn--login.a.b.c.d.verify-secure.xyz/"
        "banking/account/update/extra-long-path-segment-for-length-check"
    )
    res = evaluate_phishing_heuristics(long_url)
    rule_ids = {r.rule_id for r in res.triggered_rules}
    assert "excessive_url_length" in rule_ids
    assert "at_symbol_obfuscation" in rule_ids
    assert "excessive_subdomains" in rule_ids
    assert "suspicious_tld" in rule_ids
    assert "punycode_idn" in rule_ids
    assert "credential_keywords" in rule_ids
    assert res.phishing_probability == 1.0


def test_phishing_raw_ip_host():
    res = evaluate_phishing_heuristics("http://192.168.1.50/secure-login-verify-account-update")
    rule_ids = {r.rule_id for r in res.triggered_rules}
    assert "raw_ip_host" in rule_ids
    assert "credential_keywords" in rule_ids
    assert res.phishing_probability == 0.6


def test_threat_intel_curated_hit_and_clean(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)

    hit = check_threat_intel("http://bad-phishing-login-verify.com/login")
    assert hit.listed is True
    assert hit.hits == 1
    assert "URLhaus" in hit.source_reason

    xyz_hit = check_threat_intel("https://secure-banking-verify.xyz/auth")
    assert xyz_hit.listed is True

    clean = check_threat_intel("https://example.com")
    assert clean.listed is False
    assert clean.hits == 0


def test_threat_intel_external_hook_mocked(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "dummy-vt-key")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 4}}}
    }

    with patch("app.services.threat_intel.httpx.Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value.__enter__.return_value
        mock_client.get.return_value = mock_resp

        res = check_threat_intel("https://suspicious-external-domain.com")
        assert res.listed is True
        assert res.hits == 4
        assert res.external_lookup_used is True
        assert "VirusTotal" in res.source_reason


def test_headers_ssl_mocked_success_and_timeout():
    future_expiry = (datetime.now(timezone.utc) + timedelta(days=60)).strftime("%b %d %H:%M:%S %Y GMT")
    mock_cert = {
        "notAfter": future_expiry,
        "issuer": ((("organizationName", "Let's Encrypt"),),),
        "subject": ((("commonName", "example.com"),),),
    }

    mock_http_resp = MagicMock()
    mock_http_resp.status_code = 200
    mock_http_resp.headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "Server": "nginx/1.24.0",
    }

    with (
        patch("app.services.headers_ssl.socket.create_connection") as mock_conn,
        patch("app.services.headers_ssl.ssl.create_default_context") as mock_ctx,
        patch("app.services.headers_ssl.httpx.Client") as mock_httpx,
    ):
        mock_ssock = mock_ctx.return_value.wrap_socket.return_value.__enter__.return_value
        mock_ssock.getpeercert.return_value = mock_cert
        mock_conn.return_value.__enter__.return_value = MagicMock()
        mock_httpx.return_value.__enter__.return_value.get.return_value = mock_http_resp

        result = audit_headers_and_ssl("https://example.com")
        assert result.https_enabled is True
        assert result.status_code == 200
        assert result.ssl_certificate.valid is True
        assert result.ssl_certificate.days_until_expiration is not None
        assert result.ssl_certificate.days_until_expiration >= 59
        assert result.server_header_exposed is True
        assert result.server_header == "nginx/1.24.0"
        assert "Strict-Transport-Security" in result.present_headers
        assert "X-Frame-Options" in result.missing_headers

    with patch("app.services.headers_ssl.httpx.Client") as mock_httpx:
        mock_httpx.return_value.__enter__.return_value.get.side_effect = httpx.ConnectTimeout("Timed out")
        err_res = audit_headers_and_ssl("http://slow.example.com")
        assert err_res.status_code is None
        assert "Timed out" in (err_res.error or "")
        assert len(err_res.missing_headers) == len(REQUIRED_SECURITY_HEADERS)


def test_scoring_aggregation_and_severity():
    assert classify_severity(10) == "LOW"
    assert classify_severity(35) == "MEDIUM"
    assert classify_severity(60) == "HIGH"
    assert classify_severity(85) == "CRITICAL"

    clean_assessment = aggregate_scan_assessment(
        target_url="https://secure.example.com",
        domain="secure.example.com",
        headers_ssl=HeadersSSLResult(
            https_enabled=True,
            status_code=200,
            present_headers=list(REQUIRED_SECURITY_HEADERS),
            missing_headers=[],
            ssl_certificate=SSLCertInfo(valid=True, days_until_expiration=90),
        ),
        phishing=PhishingResult(phishing_probability=0.0),
        intel=ThreatIntelResult(listed=False, hits=0, source_reason="Clean"),
    )
    assert clean_assessment["overall_risk_score"] == 0
    assert clean_assessment["severity"] == "LOW"

    critical_assessment = aggregate_scan_assessment(
        target_url="http://bad-phishing-login-verify.com/login",
        domain="bad-phishing-login-verify.com",
        headers_ssl=HeadersSSLResult(
            https_enabled=False,
            missing_headers=list(REQUIRED_SECURITY_HEADERS),
        ),
        phishing=PhishingResult(phishing_probability=0.5),
        intel=ThreatIntelResult(listed=True, hits=1, source_reason="Reported Phishing Campaign (URLhaus)"),
    )
    assert critical_assessment["overall_risk_score"] >= 75
    assert critical_assessment["severity"] == "CRITICAL"
    assert len(critical_assessment["remediation_tips"]) >= 1

