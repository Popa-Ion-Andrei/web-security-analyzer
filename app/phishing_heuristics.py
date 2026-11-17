from urllib.parse import urlparse
import re

SUSPICIOUS_KEYWORDS = ["login", "verify", "update", "secure", "account", "banking", "confirm"]

def evaluate_phishing_risk(url: str) -> dict:
    """Calculates a heuristic phishing probability score (0.0 to 1.0) from URL structure."""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    score = 0.0
    indicators = []

    if len(url) > 75:
        score += 0.25
        indicators.append("Excessive URL length (>75 chars)")

    if "@" in url or "-" in domain:
        score += 0.25
        indicators.append("Suspicious characters (@ or hyphen) in domain")

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        score += 0.35
        indicators.append("Raw IP address used instead of domain name")

    matched_words = [w for w in SUSPICIOUS_KEYWORDS if w in url.lower()]
    if matched_words:
        score += 0.25
        indicators.append(f"Suspicious keywords detected: {', '.join(matched_words)}")

    return {
        "phishing_probability": round(min(score, 1.0), 2),
        "indicators": indicators
    }
