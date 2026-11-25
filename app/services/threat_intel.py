"""Threat intelligence domain reputation lookup with optional external API hook."""

import os
from typing import Any
from urllib.parse import urlparse
import httpx
from app.models import ThreatIntelResult

KNOWN_MALICIOUS_DOMAINS: dict[str, str] = {
    "bad-phishing-login-verify.com": "Reported Phishing Campaign (URLhaus)",
    "malware-test-distribution.org": "Known Malware Host (ThreatFox)",
    "secure-banking-verify.xyz": "Active Credential Harvesting Domain (Curated IoC Feed)",
    "example-untrusted-site.net": "Suspicious C2 Indicator",
}


def extract_domain(url: str) -> str:
    """Extracts the lowercase hostname from a URL string."""
    raw = url.strip()
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    return (parsed.hostname or "").lower()


def _query_external_intel(domain: str) -> tuple[bool, int, str | None, dict[str, Any] | None]:
    """Queries VirusTotal or URLhaus if API keys are configured via environment variables."""
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if vt_key and domain:
        try:
            with httpx.Client(timeout=3.0) as client:
                resp = client.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers={"x-apikey": vt_key},
                )
                if resp.status_code == 200:
                    stats = (
                        resp.json()
                        .get("data", {})
                        .get("attributes", {})
                        .get("last_analysis_stats", {})
                    )
                    malicious_votes = int(stats.get("malicious", 0))
                    return (
                        malicious_votes > 0,
                        malicious_votes,
                        f"VirusTotal External Feed ({malicious_votes} malicious detections)"
                        if malicious_votes > 0
                        else None,
                        {"provider": "virustotal", "last_analysis_stats": stats},
                    )
        except Exception as exc:
            return False, 0, None, {"provider": "virustotal", "error": str(exc)}

    urlhaus_key = os.getenv("URLHAUS_AUTH_KEY", "").strip()
    if urlhaus_key and domain:
        try:
            with httpx.Client(timeout=3.0) as client:
                resp = client.post(
                    "https://urlhaus-api.abuse.ch/v1/host/",
                    headers={"Auth-Key": urlhaus_key},
                    data={"host": domain},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    listed = data.get("query_status") == "ok" and int(data.get("url_count", 0)) > 0
                    count = int(data.get("url_count", 0))
                    return (
                        listed,
                        count,
                        f"URLhaus External Feed ({count} reported URLs)" if listed else None,
                        {"provider": "urlhaus", "query_status": data.get("query_status"), "url_count": count},
                    )
        except Exception as exc:
            return False, 0, None, {"provider": "urlhaus", "error": str(exc)}

    return False, 0, None, None


def check_threat_intel(url: str) -> ThreatIntelResult:
    """Checks a URL's domain against curated IoC indicators and optional external feeds."""
    domain = extract_domain(url)

    local_hit = domain in KNOWN_MALICIOUS_DOMAINS
    hits = 1 if local_hit else 0
    reason = KNOWN_MALICIOUS_DOMAINS[domain] if local_hit else "Clean / Not found in threat feeds"

    ext_used = bool(os.getenv("VIRUSTOTAL_API_KEY", "").strip() or os.getenv("URLHAUS_AUTH_KEY", "").strip())
    ext_details = None

    if ext_used and domain:
        ext_listed, ext_hits, ext_reason, ext_details = _query_external_intel(domain)
        if ext_listed:
            local_hit = True
            hits += max(ext_hits, 1)
            reason = ext_reason if reason.startswith("Clean") else f"{reason}; {ext_reason}"

    return ThreatIntelResult(
        listed=local_hit,
        hits=hits,
        source_reason=reason,
        external_lookup_used=ext_used,
        external_details=ext_details,
    )

