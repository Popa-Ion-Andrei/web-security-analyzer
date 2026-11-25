# Web & URL Security Analyzer (SIEM-Ready Edition)

A defensive, non-intrusive cybersecurity web application built with **FastAPI**, **SQLite**, **Tailwind CSS**, and **Chart.js** for inspecting HTTP security headers, TLS/SSL certificates, phishing URL heuristics, and threat intelligence indicators—exporting normalized SIEM-ready JSON events.

## Architecture Overview

```text
web-security-analyzer/
├── .github/workflows/ci.yml    # GitHub Actions (ruff + pytest)
├── app/
│   ├── main.py                 # FastAPI app, REST routes, static dashboard serving
│   ├── database.py             # SQLite persistence & analytics aggregations
│   ├── models.py               # Pydantic schemas & SIEM event models
│   └── services/
│       ├── headers_ssl.py      # HTTP headers audit, Server banner check & TLS cert inspection
│       ├── phishing.py         # Lexical phishing detector with rule-by-rule breakdown
│       ├── threat_intel.py     # Curated IoC feeds + optional VirusTotal/URLhaus hooks
│       └── scoring.py          # 0-100 risk scoring, severity tiers & remediation tips
├── static/
│   ├── index.html              # Dark SOC dashboard (Tailwind CSS & Chart.js CDN)
│   └── app.js                  # Frontend logic, charts, filters, batch & SIEM export
├── tests/
│   ├── test_services.py        # Offline unit tests for security services
│   └── test_api.py             # FastAPI TestClient integration tests (mocked HTTP/TLS)
├── Dockerfile
└── requirements.txt
```

## Key Features

- **HTTP & TLS Audit:** Inspects HTTPS status, latency, SSL certificate validity and days until expiration, exposed `Server` banner, and 6 security headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`).
- **Phishing Heuristics:** Transparent scoring (`0.0 - 1.0`) checking excessive length (`>75`), raw IP hosts, `@` obfuscation, excessive subdomains (`>3`), high-risk TLDs (`.xyz`, `.top`, `.tk`, `.ru`, `.zip`), punycode (`xn--`), and credential keywords.
- **Threat Intelligence:** Built-in curated IoC feed plus optional `VIRUSTOTAL_API_KEY` or `URLHAUS_AUTH_KEY` environment hooks.
- **SQLite Persistence & SIEM Export:** Full scan history (`GET/DELETE /api/history`), batch scanning up to 10 URLs (`POST /api/scan/batch`), KPI analytics (`GET /api/stats`), and downloadable NDJSON/JSON SIEM logs (`GET /api/export/siem`).

## Local Setup

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open **`http://127.0.0.1:8000/`** for the SOC Dark Dashboard or **`http://127.0.0.1:8000/docs`** for Swagger API Docs.

### Running Tests & Linter

```bash
ruff check .
PYTHONPATH=. pytest -v
```

*(On Windows PowerShell: `$env:PYTHONPATH="."; pytest -v`)*

## Docker Usage

```bash
docker build -t web-security-analyzer .
docker run -d -p 8000:8000 --name security-analyzer web-security-analyzer
```
