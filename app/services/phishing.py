"""Heuristic phishing URL detector with transparent rule breakdown."""

import ipaddress
from urllib.parse import urlparse
from app.models import PhishingResult, PhishingRuleHit

SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".ru", ".zip"}
CREDENTIAL_KEYWORDS = ["login", "verify", "secure", "banking", "account", "update"]


def _is_raw_ip(hostname: str) -> bool:
    """Checks whether the hostname is a literal IPv4 or IPv6 address."""
    cleaned = hostname.strip("[]")
    try:
        ipaddress.ip_address(cleaned)
        return True
    except ValueError:
        return False


def evaluate_phishing_heuristics(url: str) -> PhishingResult:
    """Evaluates URL lexical patterns and returns a 0.0-1.0 risk probability with rule breakdown."""
    raw = url.strip()
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    hostname = (parsed.hostname or "").lower()

    score = 0.0
    triggered_rules: list[PhishingRuleHit] = []

    if len(raw) > 75:
        weight = 0.20
        score += weight
        triggered_rules.append(
            PhishingRuleHit(
                rule_id="excessive_url_length",
                description=f"Excessive URL length ({len(raw)} chars > 75)",
                weight=weight,
            )
        )

    is_ip = bool(hostname) and _is_raw_ip(hostname)
    if is_ip:
        weight = 0.35
        score += weight
        triggered_rules.append(
            PhishingRuleHit(
                rule_id="raw_ip_host",
                description=f"Raw IP address used as host ({hostname})",
                weight=weight,
            )
        )

    if "@" in raw:
        weight = 0.25
        score += weight
        triggered_rules.append(
            PhishingRuleHit(
                rule_id="at_symbol_obfuscation",
                description="URL contains '@' credential obfuscation symbol",
                weight=weight,
            )
        )

    if hostname and not is_ip:
        labels = [part for part in hostname.split(".") if part]
        subdomain_count = max(0, len(labels) - 2)
        if subdomain_count > 3:
            weight = 0.20
            score += weight
            triggered_rules.append(
                PhishingRuleHit(
                    rule_id="excessive_subdomains",
                    description=f"Excessive subdomains detected ({subdomain_count} > 3)",
                    weight=weight,
                )
            )

        if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
            matched_tld = next(tld for tld in SUSPICIOUS_TLDS if hostname.endswith(tld))
            weight = 0.20
            score += weight
            triggered_rules.append(
                PhishingRuleHit(
                    rule_id="suspicious_tld",
                    description=f"High-risk TLD detected ({matched_tld})",
                    weight=weight,
                )
            )

        if "xn--" in hostname:
            weight = 0.30
            score += weight
            triggered_rules.append(
                PhishingRuleHit(
                    rule_id="punycode_idn",
                    description="Punycode internationalized domain ('xn--') detected",
                    weight=weight,
                )
            )

    matched_keywords = [kw for kw in CREDENTIAL_KEYWORDS if kw in raw.lower()]
    if matched_keywords:
        weight = 0.25
        score += weight
        triggered_rules.append(
            PhishingRuleHit(
                rule_id="credential_keywords",
                description=f"Credential-targeting keywords detected: {', '.join(matched_keywords)}",
                weight=weight,
            )
        )

    probability = round(min(score, 1.0), 2)
    indicators = [rule.description for rule in triggered_rules]

    return PhishingResult(
        phishing_probability=probability,
        triggered_rules=triggered_rules,
        indicators=indicators,
    )

