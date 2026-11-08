import httpx

REQUIRED_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options"
]

def check_security_headers(url: str) -> dict:
    """Inspects HTTP response headers defensively for missing security policies."""
    missing = []
    present = []
    try:
        with httpx.Client(timeout=5.0, follow_redirects=True) as client:
            response = client.get(url)
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            for req in REQUIRED_SECURITY_HEADERS:
                if req.lower() in headers:
                    present.append(req)
                else:
                    missing.append(req)
                    
            return {
                "status_code": response.status_code,
                "https_enabled": url.startswith("https://"),
                "present_headers": present,
                "missing_headers": missing
            }
    except Exception as e:
        return {
            "status_code": None,
            "https_enabled": url.startswith("https://"),
            "present_headers": [],
            "missing_headers": REQUIRED_SECURITY_HEADERS,
            "error": str(e)
        }