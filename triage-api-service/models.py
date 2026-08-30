from enum import Enum
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IncidentStatus(str, Enum):
    NEW = "new"
    TRIAGING = "triaging"
    TRIAGED = "triaged"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class AlertIn(BaseModel):
    source: str = Field(..., description="Origin system of the alert")
    fingerprint: str = Field(..., description="Dedup key from the rules engine")
    title: str = Field(..., description="Short alert description")
    description: str = "", extra: dict = Field(default_factory=dict)
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    labels: list[str] = Field(default_factory=list)


class TriageUpdate(BaseModel):
    severity: Optional[Severity] = None
    status: Optional[IncidentStatus] = None
    assignee: Optional[str] = None
    notes: Optional[str] = None


class IncidentOut(BaseModel):
    id: str
    fingerprint: str
    source: str
    title: str
    description: str
    severity: Severity
    status: IncidentStatus
    assignee: Optional[str] = None
    notes: Optional[str] = None
    alert_count: int = 1
    extra: dict = Field(default_factory=dict)
    labels: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class ErrorResponse(BaseModel):
    detail: str


def classify_severity(alert: AlertIn) -> Severity:
    text = (alert.title + " " + alert.description).lower()
    critical_kw = ["outage", "down", "data loss", "breach", "unavailable"]
    high_kw = ["degraded", "error spike", "latency", "failover"]
    medium_kw = ["warning", "threshold", "retry", "slow"]
    if alert.confidence >= 0.9 and any(k in text for k in critical_kw):
        return Severity.CRITICAL
    if any(k in text for k in critical_kw):
        return Severity.HIGH
    if any(k in text for k in high_kw):
        return Severity.HIGH
    if any(k in text for k in medium_kw):
        return Severity.MEDIUM
    if alert.confidence < 0.3:
        return Severity.INFO
    return Severity.LOW