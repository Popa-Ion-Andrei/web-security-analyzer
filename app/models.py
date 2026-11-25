"""Pydantic schemas for scan requests, module outputs, history, and SIEM events."""

from typing import Any, Literal, Optional
from pydantic import BaseModel, Field

SeverityLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class ScanRequest(BaseModel):
    """Request payload for scanning a single URL."""

    url: str = Field(..., min_length=1, max_length=2048, description="Target URL to inspect")


class BatchScanRequest(BaseModel):
    """Request payload for scanning up to 10 URLs in one batch."""

    urls: list[str] = Field(
        ...,
        min_length=1,
        max_length=10,
        description="List of up to 10 URLs to analyze",
    )


class SSLCertInfo(BaseModel):
    """TLS/SSL certificate metadata and expiration details."""

    valid: Optional[bool] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    expires_at: Optional[str] = None
    days_until_expiration: Optional[int] = None
    error: Optional[str] = None


class HeadersSSLResult(BaseModel):
    """Result from the HTTP security headers and TLS certificate audit."""

    https_enabled: bool
    status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    present_headers: list[str] = Field(default_factory=list)
    missing_headers: list[str] = Field(default_factory=list)
    server_header: Optional[str] = None
    server_header_exposed: bool = False
    ssl_certificate: SSLCertInfo = Field(default_factory=SSLCertInfo)
    error: Optional[str] = None


class PhishingRuleHit(BaseModel):
    """Represents a single heuristic rule triggered during URL inspection."""

    rule_id: str
    description: str
    weight: float


class PhishingResult(BaseModel):
    """Result from the heuristic phishing URL analyzer."""

    phishing_probability: float
    triggered_rules: list[PhishingRuleHit] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)


class ThreatIntelResult(BaseModel):
    """Result from domain threat intelligence feed lookup."""

    listed: bool
    hits: int
    source_reason: str
    external_lookup_used: bool = False
    external_details: Optional[dict[str, Any]] = None


class ScanModules(BaseModel):
    """Grouped outputs from the three defensive analysis modules."""

    http_tls_audit: HeadersSSLResult
    phishing_analysis: PhishingResult
    threat_intelligence: ThreatIntelResult


class SIEMEvent(BaseModel):
    """Normalized SIEM-compatible JSON log event."""

    event_id: str
    timestamp: str
    source: str = "web-security-analyzer"
    event_type: str = "url_security_assessment"
    target_url: str
    domain: str
    overall_risk_score: int
    severity: SeverityLevel
    remediation_tips: list[str]
    modules: ScanModules


class ScanResponse(BaseModel):
    """Complete scan result persisted in SQLite and returned by API routes."""

    id: int
    timestamp: str
    target_url: str
    domain: str
    overall_risk_score: int
    severity: SeverityLevel
    remediation_tips: list[str]
    modules: ScanModules
    siem_event: SIEMEvent


class BatchScanResponse(BaseModel):
    """Summary response for a batch scan request."""

    count: int
    results: list[ScanResponse]


class ScanHistoryItem(BaseModel):
    """Compact scan history record returned by list endpoints."""

    id: int
    timestamp: str
    target_url: str
    domain: str
    overall_risk_score: int
    severity: SeverityLevel
    missing_headers: list[str]


class TopMissingHeader(BaseModel):
    """Count of scans missing a given security header."""

    header: str
    count: int


class StatsResponse(BaseModel):
    """Dashboard KPI and chart analytics payload."""

    total_scans: int
    critical_high_count: int
    clean_count: int
    avg_risk_score: float
    severity_distribution: dict[str, int]
    top_missing_headers: list[TopMissingHeader]

