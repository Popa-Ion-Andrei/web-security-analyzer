from urllib.parse import urlparse

KNOWN_MALICIOUS_DOMAINS = {
    "bad-phishing-login-verify.com": "Reported Phishing Campaign (URLhaus)",
    "malware-test-distribution.org": "Known Malware Host (ThreatFox)",
    "example-untrusted-site.net": "Suspicious C2 Indicator"
}

def check_threat_intelligence(url: str) -> dict:
    """Checks domain reputation against threat intelligence indicators."""
    domain = urlparse(url).netloc.lower()
    if domain in KNOWN_MALICIOUS_DOMAINS:
        return {
            "listed": True,
            "hits": 1,
            "source_reason": KNOWN_MALICIOUS_DOMAINS[domain]
        }
    return {
        "listed": False,
        "hits": 0,
        "source_reason": "Clean / Not found in threat feeds"
    }
