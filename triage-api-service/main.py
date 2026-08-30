import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from models import AlertIn, IncidentOut, TriageUpdate, Severity, IncidentStatus, classify_severity, ErrorResponse

app = FastAPI(title="Incident Triage Service", version="0.1.0")
logger = logging.getLogger("triage")

# In-memory store: fingerprint -> IncidentOut
_incidents: dict[str, IncidentOut] = {}
# Reverse index: id -> fingerprint
_id_to_fp: dict[str, str] = {}


def _incident_id(fingerprint: str) -> str:
    return hashlib.sha256(fingerprint.encode()).hexdigest()[:16]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _notify_slack(incident: IncidentOut) -> None:
    logger.info("SLACK webhook: incident %s severity=%s", incident.id, incident.severity)


def _notify_pagerduty(incident: IncidentOut) -> None:
    if incident.severity in (Severity.CRITICAL, Severity.HIGH):
        logger.info("PAGERDUTY dispatch: incident %s severity=%s", incident.id, incident.severity)


def _dispatch_notifications(incident: IncidentOut) -> None:
    _notify_slack(incident)
    _notify_pagerduty(incident)


@app.post("/incidents", response_model=IncidentOut, status_code=201,
           responses={201: {"model": IncidentOut}})
def submit_alert(alert: AlertIn):
    fp = alert.fingerprint
    if fp in _incidents:
        existing = _incidents[fp]
        existing.alert_count += 1
        existing.updated_at = _now()
        existing.labels = sorted(set(existing.labels + alert.labels))
        logger.info("Correlated alert to existing incident %s (count=%d)", existing.id, existing.alert_count)
        _dispatch_notifications(existing)
        return existing

    inc_id = _incident_id(fp)
    severity = classify_severity(alert)
    incident = IncidentOut(
        id=inc_id, fingerprint=fp, source=alert.source, title=alert.title,
        description=alert.description, severity=severity, status=IncidentStatus.NEW,
        extra=alert.extra, labels=alert.labels, created_at=_now(), updated_at=_now(),
    )
    _incidents[fp] = incident
    _id_to_fp[inc_id] = fp
    logger.info("Created incident %s severity=%s fingerprint=%s", inc_id, severity, fp)
    _dispatch_notifications(incident)
    return incident


@app.get("/incidents/{incident_id}", response_model=IncidentOut,
         responses={404: {"model": ErrorResponse}})
def get_incident(incident_id: str):
    fp = _id_to_fp.get(incident_id)
    if not fp or fp not in _incidents:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _incidents[fp]


@app.patch("/incidents/{incident_id}/triage", response_model=IncidentOut,
           responses={404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}})
def update_triage(incident_id: str, update: TriageUpdate):
    fp = _id_to_fp.get(incident_id)
    if not fp or fp not in _incidents:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident = _incidents[fp]

    if incident.status == IncidentStatus.RESOLVED:
        raise HTTPException(status_code=409, detail="Cannot triage a resolved incident")

    if update.severity is not None:
        incident.severity = update.severity
    if update.status is not None:
        incident.status = update.status
    if update.assignee is not None:
        incident.assignee = update.assignee
    if update.notes is not None:
        incident.notes = update.notes

    incident.updated_at = _now()
    logger.info("Triage updated for %s: severity=%s status=%s assignee=%s",
                incident.id, incident.severity, incident.status, incident.assignee)
    _dispatch_notifications(incident)
    return incident


@app.get("/health")
def health():
    return {"status": "ok", "incidents_tracked": len(_incidents)}