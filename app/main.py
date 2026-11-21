from datetime import datetime, timezone
from fastapi import FastAPI, Query
from app.headers_audit import check_security_headers
from app.phishing_heuristics import evaluate_phishing_risk
from app.threat_intel import check_threat_intelligence

app = FastAPI(
    title="Web & URL Security Analyzer",
    description="Modular security posture & phishing analyzer exporting SIEM-ready JSON events.",
    version="1.0.0"
)

@app.get("/health")
def health_check():
    return {"status": "healthy"}

@app.get("/analyze")
def analyze_url(target_url: str = Query(..., description="URL to inspect (e.g. https://example.com)")):
    headers_res = check_security_headers(target_url)
    phishing_res = evaluate_phishing_risk(target_url)
    intel_res = check_threat_intelligence(target_url)

    # Calculate unified risk level for SIEM ingestion
    risk_level = "LOW"
    if intel_res["listed"] or phishing_res["phishing_probability"] >= 0.6:
        risk_level = "HIGH"
    elif len(headers_res["missing_headers"]) >= 2 or phishing_res["phishing_probability"] >= 0.25:
        risk_level = "MEDIUM"

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_url": target_url,
        "overall_risk_score": risk_level,
        "modules": {
            "http_security_audit": headers_res,
            "phishing_analysis": phishing_res,
            "threat_intelligence": intel_res
        }
    }
