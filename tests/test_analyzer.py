from app.phishing_heuristics import evaluate_phishing_risk
from app.threat_intel import check_threat_intelligence

def test_clean_url_phishing_score():
    res = evaluate_phishing_risk("https://example.com")
    assert res["phishing_probability"] == 0.0

def test_suspicious_url_phishing_score():
    res = evaluate_phishing_risk("http://192.168.1.1/login-verify-account-update")
    assert res["phishing_probability"] >= 0.5
    assert len(res["indicators"]) >= 2

def test_threat_intel_hit():
    res = check_threat_intelligence("http://bad-phishing-login-verify.com/login")
    assert res["listed"] is True
    assert res["hits"] == 1
