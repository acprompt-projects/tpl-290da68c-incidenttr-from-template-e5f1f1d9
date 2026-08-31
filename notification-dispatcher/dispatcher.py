import time
import threading
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable
import logging
import json
import hashlib

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Channel(str, Enum):
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    EMAIL = "email"


@dataclass
class Incident:
    id: str
    title: str
    severity: Severity
    category: str
    description: str
    metadata: Dict = field(default_factory=dict)
    dedup_key: Optional[str] = None


@dataclass
class RoutingRule:
    severities: List[Severity]
    categories: List[str]
    channels: List[Channel]

    def matches(self, incident: Incident) -> bool:
        sev_ok = incident.severity in self.severities
        cat_ok = not self.categories or incident.category in self.categories or "*" in self.categories
        return sev_ok and cat_ok


class RateLimiter:
    def __init__(self, max_calls: int, period_seconds: float):
        self.max_calls = max_calls
        self.period_seconds = period_seconds
        self._calls: List[float] = []
        self._lock = threading.Lock()

    def acquire(self) -> bool:
        with self._lock:
            now = time.monotonic()
            cutoff = now - self.period_seconds
            self._calls = [t for t in self._calls if t > cutoff]
            if len(self._calls) >= self.max_calls:
                return False
            self._calls.append(now)
            return True


class SlackSender:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send(self, incident: Incident) -> bool:
        color = {"critical": "#ff0000", "high": "#ff6600", "medium": "#ffcc00",
                 "low": "#3399ff", "info": "#999999"}.get(incident.severity.value, "#999999")
        payload = {
            "text": f"[{incident.severity.value.upper()}] {incident.title}",
            "attachments": [{
                "color": color,
                "fields": [
                    {"title": "Category", "value": incident.category, "short": True},
                    {"title": "Incident ID", "value": incident.id, "short": True},
                    {"title": "Description", "value": incident.description, "short": False},
                ]
            }]
        }
        logger.info("Slack dispatch: %s", json.dumps(payload))
        return True


class PagerDutySender:
    def __init__(self, routing_key: str, api_url: str = "https://events.pagerduty.com/v2/enqueue"):
        self.routing_key = routing_key
        self.api_url = api_url

    def send(self, incident: Incident) -> bool:
        severity_map = {"critical": "critical", "high": "error", "medium": "warning", "low": "info", "info": "info"}
        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "dedup_key": incident.dedup_key or hashlib.sha256(incident.id.encode()).hexdigest()[:16],
            "payload": {
                "summary": f"[{incident.severity.value.upper()}] {incident.title}",
                "severity": severity_map.get(incident.severity.value, "info"),
                "source": incident.metadata.get("source", "incident-triage"),
                "component": incident.category,
                "custom_details": {"description": incident.description, "incident_id": incident.id},
            }
        }
        logger.info("PagerDuty dispatch: %s", json.dumps(payload))
        return True


class EmailSender:
    def __init__(self, smtp_host: str = "localhost", smtp_port: int = 587,
                 recipients: Optional[List[str]] = None):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.recipients = recipients or []

    def send(self, incident: Incident) -> bool:
        message = {
            "to": self.recipients,
            "subject": f"[{incident.severity.value.upper()}] {incident.title}",
            "body": f"Incident: {incident.id}\nCategory: {incident.category}\n\n{incident.description}"
        }
        logger.info("Email dispatch: %s", json.dumps(message))
        return True


DEFAULT_ROUTING_RULES = [
    RoutingRule(severities=[Severity.CRITICAL], categories=["*"],
                channels=[Channel.SLACK, Channel.PAGERDUTY, Channel.EMAIL]),
    RoutingRule(severities=[Severity.HIGH], categories=["*"],
                channels=[Channel.SLACK, Channel.PAGERDUTY]),
    RoutingRule(severities=[Severity.MEDIUM], categories=["security", "infra"],
                channels=[Channel.SLACK, Channel.EMAIL]),
    RoutingRule(severities=[Severity.MEDIUM], categories=["*"],
                channels=[Channel.SLACK]),
    RoutingRule(severities=[Severity.LOW, Severity.INFO], categories=["*"],
                channels=[Channel.EMAIL]),
]

DEFAULT_RATE_LIMITS = {
    Channel.SLACK: RateLimiter(30, 60.0),
    Channel.PAGERDUTY: RateLimiter(10, 60.0),
    Channel.EMAIL: RateLimiter(60, 60.0),
}


class NotificationDispatcher:
    def __init__(self, routing_rules: Optional[List[RoutingRule]] = None,
                 rate_limits: Optional[Dict[Channel, RateLimiter]] = None,
                 senders: Optional[Dict[Channel, Callable]] = None):
        self.routing_rules = routing_rules or DEFAULT_ROUTING_RULES
        self.rate_limits = rate_limits or DEFAULT_RATE_LIMITS
        self.senders: Dict[Channel, Callable] = senders or {}
        self._dispatch_log: List[Dict] = []
        self._lock = threading.Lock()

    def register_sender(self, channel: Channel, sender: Callable):
        self.senders[channel] = sender

    def resolve_channels(self, incident: Incident) -> List[Channel]:
        channels = []
        for rule in self.routing_rules:
            if rule.matches(incident):
                for ch in rule.channels:
                    if ch not in channels:
                        channels.append(ch)
        return channels

    def dispatch(self, incident: Incident) -> Dict[str, bool]:
        channels = self.resolve_channels(incident)
        results: Dict[str, bool] = {}
        for channel in channels:
            limiter = self.rate_limits.get(channel)
            if limiter and not limiter.acquire():
                logger.warning("Rate limited on %s for incident %s", channel.value, incident.id)
                results[channel.value] = False
                self._log_dispatch(incident, channel, "rate_limited")
                continue
            sender = self.senders.get(channel)
            if not sender:
                logger.warning("No sender registered for %s", channel.value)
                results[channel.value] = False
                self._log_dispatch(incident, channel, "no_sender")
                continue
            try:
                ok = sender.send(incident)
                results[channel.value] = ok
                self._log_dispatch(incident, channel, "sent" if ok else "send_failed")
            except Exception as exc:
                logger.exception("Error sending to %s: %s", channel.value, exc)
                results[channel.value] = False
                self._log_dispatch(incident, channel, f"error:{exc}")
        return results

    def _log_dispatch(self, incident: Incident, channel: Channel, status: str):
        entry = {"incident_id": incident.id, "channel": channel.value,
                 "severity": incident.severity.value, "category": incident.category,
                 "status": status, "timestamp": time.time()}
        with self._lock:
            self._dispatch_log.append(entry)

    def get_dispatch_log(self, limit: int = 100) -> List[Dict]:
        with self._lock:
            return list(self._dispatch_log[-limit:])