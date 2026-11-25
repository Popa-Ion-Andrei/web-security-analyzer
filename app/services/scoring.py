"""Risk score aggregation, severity classification, remediation guidance, and SIEM formatting."""

from datetime import datetime, timezone
import uuid
from app.models import (
    HeadersSSLResult,
    PhishingResult,
    SIEMEvent,
    ScanModules,
    SeverityLevel,
    ThreatIntelResult,
)

HEADER_REMEDIATIONS: dict[str, str] = {
    "Strict-Transport-Security": "Enable Strict-Transport-Security (HSTS) to force HTTPS connections and block protocol downgrade attacks.",
    "Content-Security-Policy": "Configure Content-Security-Policy (CSP) to restrict script origins and mitigate XSS attacks.",
    "X-Frame-Options": "Add X-Frame-Options (DENY or SAMEORIGIN) to defend against clickjacking.",
    "X-Content-Type-Options": "Set X-Content-Type-Options: nosniff to prevent MIME-type sniffing.",
    "Referrer-Policy": "Add Referrer-Policy (e.g., strict-origin-when-cross-origin) to limit referrer leakage.",
    "Permissions-Policy": "Define Permissions-Policy to restrict unnecessary browser APIs (camera, geolocation, microphone).",
}


def classify_severity(score: int) -> SeverityLevel:
    """Maps a 0-100 risk score to a normalized severity tier."""
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def build_remediation_tips(
    headers_ssl: HeadersSSLResult,
    phishing: PhishingResult,
    intel: ThreatIntelResult,
) -> list[str]:
    """Generates actionable, prioritized remediation steps based on detected findings."""
    tips: list[str] = []

    if intel.listed:
        tips.append(
            f"Block domain immediately at DNS/proxy/firewall layers ({intel.source_reason}) and search SIEM logs for prior outbound connections."
        )

    if phishing.triggered_rules:
        tips.append(
            "Verify domain ownership manually and warn users against suspicious URL patterns (raw IP hosts, punycode, suspicious TLDs, or credential lures)."
        )

    if not headers_ssl.https_enabled:
        tips.append("Migrate target endpoint to HTTPS with valid TLS 1.2/1.3 certificates.")

    cert = headers_ssl.ssl_certificate
    if headers_ssl.https_enabled and cert.valid is False:
        tips.append("Replace or repair the invalid/expired TLS certificate to prevent MITM exposure and trust errors.")
    elif cert.days_until_expiration is not None and cert.days_until_expiration < 30:
        tips.append(f"Renew the TLS certificate soon (expires in {cert.days_until_expiration} days).")

    if headers_ssl.server_header_exposed:
        tips.append(
            f"Remove or obfuscate the exposed 'Server: {headers_ssl.server_header}' header to reduce server fingerprinting."
        )

    if not headers_ssl.error:
        for missing_hdr in headers_ssl.missing_headers:
            if missing_hdr in HEADER_REMEDIATIONS:
                tips.append(HEADER_REMEDIATIONS[missing_hdr])

    if not tips:
        tips.append("Security posture is healthy. Continue monitoring TLS expiration and security header policies.")

    return tips


def aggregate_scan_assessment(
    target_url: str,
    domain: str,
    headers_ssl: HeadersSSLResult,
    phishing: PhishingResult,
    intel: ThreatIntelResult,
) -> dict:
    """Computes overall risk score (0-100), severity, remediation tips, and SIEM JSON event."""
    score = 0

    if intel.listed:
        score += 55

    score += int(round(phishing.phishing_probability * 45))

    if not headers_ssl.https_enabled:
        score += 15

    cert = headers_ssl.ssl_certificate
    if headers_ssl.https_enabled and cert.valid is False:
        score += 15
    elif cert.days_until_expiration is not None:
        if cert.days_until_expiration < 14:
            score += 12
        elif cert.days_until_expiration < 30:
            score += 6

    if headers_ssl.server_header_exposed:
        score += 4

    # When HTTP fails (e.g., unreachable fake phishing host), avoid inflating clean unreachable domains
    # while still factoring in missing security headers cleanly.
    score += len(headers_ssl.missing_headers) * 3

    if headers_ssl.error and not intel.listed and phishing.phishing_probability == 0:
        score = max(score, 25)

    overall_risk_score = max(0, min(100, score))
    if intel.listed:
        overall_risk_score = max(overall_risk_score, 75)

    severity = classify_severity(overall_risk_score)
    remediation_tips = build_remediation_tips(headers_ssl, phishing, intel)
    timestamp = datetime.now(timezone.utc).isoformat()

    modules = ScanModules(
        http_tls_audit=headers_ssl,
        phishing_analysis=phishing,
        threat_intelligence=intel,
    )

    siem_event = SIEMEvent(
        event_id=str(uuid.uuid4()),
        timestamp=timestamp,
        target_url=target_url,
        domain=domain,
        overall_risk_score=overall_risk_score,
        severity=severity,
        remediation_tips=remediation_tips,
        modules=modules,
    )

    return {
        "timestamp": timestamp,
        "target_url": target_url,
        "domain": domain,
        "overall_risk_score": overall_risk_score,
        "severity": severity,
        "remediation_tips": remediation_tips,
        "modules": modules.model_dump(),
        "siem_event": siem_event.model_dump(),
    }

