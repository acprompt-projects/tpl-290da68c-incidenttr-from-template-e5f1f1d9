import os
from typing import Optional, List
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from dispatcher import (
    NotificationDispatcher, Incident, Severity, Channel,
    RoutingRule, RateLimiter, SlackSender, PagerDutySender, EmailSender,
)

app = FastAPI(title="Notification Dispatcher", version="1.0.0")

dispatcher = NotificationDispatcher()

_slack_webhook = os.getenv("SLACK_WEBHOOK_URL")
_pd_routing_key = os.getenv("PAGERDUTY_ROUTING_KEY")

if _slack_webhook:
    dispatcher.register_sender(Channel.SLACK, SlackSender(_slack_webhook))
if _pd_routing_key:
    dispatcher.register_sender(Channel.PAGERDUTY, PagerDutySender(_pd_routing_key))

_email_recipients = os.getenv("EMAIL_RECIPIENTS", "")
if _email_recipients:
    dispatcher.register_sender(Channel.EMAIL, EmailSender(recipients=_email_recipients.split(",")))


class IncidentPayload(BaseModel):
    id: str
    title: str
    severity: Severity
    category: str
    description: str = ""
    metadata: dict = Field(default_factory=dict)
    dedup_key: Optional[str] = None


class DispatchResponse(BaseModel):
    incident_id: str
    channels: dict


class RoutingRulePayload(BaseModel):
    severities: List[Severity]
    categories: List[str]
    channels: List[Channel]


class DispatchLogResponse(BaseModel):
    log: List[dict]


@app.post("/dispatch", response_model=DispatchResponse)
def dispatch_incident(payload: IncidentPayload):
    incident = Incident(**payload.model_dump())
    results = dispatcher.dispatch(incident)
    return DispatchResponse(incident_id=incident.id, channels=results)


@app.post("/resolve", response_model=dict)
def resolve_channels(payload: IncidentPayload):
    incident = Incident(**payload.model_dump())
    channels = dispatcher.resolve_channels(incident)
    return {"incident_id": incident.id, "channels": [c.value for c in channels]}


@app.get("/routing-rules")
def get_routing_rules():
    return [{"severities": [s.value for s in r.severities],
             "categories": r.categories,
             "channels": [c.value for c in r.channels]} for r in dispatcher.routing_rules]


@app.put("/routing-rules")
def set_routing_rules(rules: List[RoutingRulePayload]):
    dispatcher.routing_rules = [
        RoutingRule(severities=r.severities, categories=r.categories, channels=r.channels)
        for r in rules
    ]
    return {"count": len(dispatcher.routing_rules)}


@app.get("/dispatch-log", response_model=DispatchLogResponse)
def get_dispatch_log(limit: int = 100):
    return DispatchLogLogResponse(log=dispatcher.get_dispatch_log(limit=limit))


@app.get("/health")
def health():
    senders = {ch.value: (ch in dispatcher.senders) for ch in Channel}
    return {"status": "ok", "senders": senders}