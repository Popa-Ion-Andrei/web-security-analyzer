"""HTTP security headers and TLS/SSL certificate inspection service."""

from datetime import datetime, timezone
import socket
import ssl
import time
from urllib.parse import urlparse
import httpx
from app.models import HeadersSSLResult, SSLCertInfo

REQUIRED_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def _extract_cert_field(entries: tuple, target_key: str) -> str | None:
    """Extracts a named field (e.g. commonName, organizationName) from a peer cert tuple."""
    for rdn in entries:
        for key, value in rdn:
            if key == target_key:
                return str(value)
    return None


def inspect_ssl_certificate(hostname: str, port: int = 443, timeout: float = 4.0) -> SSLCertInfo:
    """Inspects a host's TLS certificate validity and expiration window."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        return SSLCertInfo(valid=False, error=f"SSL verification failed: {exc}")
    except (ssl.SSLError, TimeoutError, OSError) as exc:
        return SSLCertInfo(valid=False, error=f"TLS connection error: {exc}")

    if not cert:
        return SSLCertInfo(valid=False, error="No peer certificate presented")

    not_after_raw = cert.get("notAfter")
    expires_at: str | None = None
    days_remaining: int | None = None
    valid = True

    if not_after_raw:
        try:
            expiry_dt = datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            expires_at = expiry_dt.isoformat()
            days_remaining = int((expiry_dt - datetime.now(timezone.utc)).total_seconds() // 86400)
            if days_remaining < 0:
                valid = False
        except ValueError:
            expires_at = str(not_after_raw)

    issuer = _extract_cert_field(cert.get("issuer", ()), "organizationName") or _extract_cert_field(
        cert.get("issuer", ()), "commonName"
    )
    subject = _extract_cert_field(cert.get("subject", ()), "commonName")

    return SSLCertInfo(
        valid=valid,
        issuer=issuer,
        subject=subject,
        expires_at=expires_at,
        days_until_expiration=days_remaining,
    )


def audit_headers_and_ssl(url: str, timeout: float = 5.0) -> HeadersSSLResult:
    """Audits HTTP security headers, Server banner exposure, latency, and SSL/TLS state."""
    parsed = urlparse(url.strip())
    https_enabled = parsed.scheme.lower() == "https"
    ssl_info = SSLCertInfo()

    if https_enabled and parsed.hostname:
        port = parsed.port or 443
        ssl_info = inspect_ssl_certificate(parsed.hostname, port=port, timeout=min(timeout, 4.0))

    if parsed.scheme.lower() not in {"http", "https"}:
        return HeadersSSLResult(
            https_enabled=False,
            missing_headers=list(REQUIRED_SECURITY_HEADERS),
            ssl_certificate=ssl_info,
            error=f"Unsupported or missing URL protocol '{parsed.scheme or 'none'}' (expected http:// or https://).",
        )

    start = time.perf_counter()
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            response = client.get(url)
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            headers_lower = {k.lower(): v for k, v in response.headers.items()}

            present: list[str] = []
            missing: list[str] = []
            for req in REQUIRED_SECURITY_HEADERS:
                if req.lower() in headers_lower:
                    present.append(req)
                else:
                    missing.append(req)

            server_banner = headers_lower.get("server")
            return HeadersSSLResult(
                https_enabled=https_enabled,
                status_code=response.status_code,
                response_time_ms=elapsed_ms,
                present_headers=present,
                missing_headers=missing,
                server_header=server_banner,
                server_header_exposed=bool(server_banner),
                ssl_certificate=ssl_info,
            )
    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        return HeadersSSLResult(
            https_enabled=https_enabled,
            response_time_ms=elapsed_ms,
            missing_headers=list(REQUIRED_SECURITY_HEADERS),
            ssl_certificate=ssl_info,
            error=str(exc),
        )

