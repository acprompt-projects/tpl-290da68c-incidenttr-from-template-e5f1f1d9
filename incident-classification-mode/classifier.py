===
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

class Severity(Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"

class Category(Enum):
    INFRA = "infra"
    APP = "app"
    SECURITY = "security"
    NETWORK = "network"

@dataclass
class TriageLabel:
    severity: Severity
    category: Category
    confidence: float
    rule_ids: list[str]
    reasoning: str

@dataclass
class Incident:
    title: str
    description: str
    source: str
    tags: list[str]
    metric_name: Optional[str] = None
    metric_value: Optional[float] = None
    affected_service: Optional[str] = None
    error_rate: Optional[float] = None
    latency_ms: Optional[float] = None

DEFAULT_THRESHOLDS = {
    "error_rate": {Severity.P1: 0.50, Severity.P2: 0.25, Severity.P3: 0.10, Severity.P4: 0.0},
    "latency_ms": {Severity.P1: 5000, Severity.P2: 2000, Severity.P3: 1000, Severity.P4: 0},
    "confidence_floor": 0.3,
}

CATEGORY_KEYWORDS: dict[Category, dict[str, list[str]]] = {
    Category.INFRA: {
        "title": ["cpu", "memory", "disk", "oom", "out of memory", "host", "node", "server", "pod", "vm", "instance", "capacity", "resource"],
        "tags": ["infra", "hardware", "compute", "storage", "kubernetes", "k8s"],
        "source": ["prometheus", "node-exporter", "cadvisor", "cloudwatch"],
    },
    Category.APP: {
        "title": ["error", "exception", "crash", "timeout", "5xx", "500", "fail", "panic", "deploy", "rollback", "bug"],
        "tags": ["app", "application", "service", "api", "microservice", "backend", "frontend"],
        "source": ["sentry", "datadog", "appdynamics", "newrelic"],
    },
    Category.SECURITY: {
        "title": ["breach", "unauthorized", "auth", "login", "intrusion", "malware", "vulnerability", "cve", "exploit", "ddos", "brute", "ssl", "tls", "certificate"],
        "tags": ["security", "auth", "iam", "firewall", "waf", "compliance"],
        "source": ["guardduty", "crowdstrike", "snort", "suricata"],
    },
    Category.NETWORK: {
        "title": ["dns", "latency", "packet", "connection", "refused", "unreachable", "network", "routing", "firewall drop", "tcp", "tls handshake"],
        "tags": ["network", "dns", "cdn", "proxy", "loadbalancer", "vpn"],
        "source": ["pingdom", "thousandeyes", "cloudflare", "nginx"],
    },
}

def _score_category(incident: Incident) -> dict[Category, float]:
    scores: dict[Category, float] = {c: 0.0 for c in Category}
    text_fields = [
        incident.title.lower(),
        incident.description.lower(),
    ]
    combined_text = " ".join(text_fields)
    combined_tags = " ".join(t.lower() for t in incident.tags)
    source_lower = incident.source.lower()

    for cat, patterns in CATEGORY_KEYWORDS.items():
        for kw in patterns["title"]:
            if kw in combined_text:
                scores[cat] += 2.0
        for kw in patterns["tags"]:
            if kw in combined_tags:
                scores[cat] += 1.5
            elif kw in combined_text:
                scores[cat] += 0.5
        for kw in patterns["source"]:
            if kw in source_lower:
                scores[cat] += 2.0
    return scores

def _classify_category(incident: Incident) -> tuple[Category, float]:
    scores = _score_category(incident)
    best_cat = max(scores, key=lambda c: scores[c])
    total = sum(scores.values()) or 1.0
    confidence = scores[best_cat] / total if scores[best_cat] > 0 else 0.25
    return best_cat, min(confidence, 1.0)

def _classify_severity(incident: Incident, thresholds: dict) -> tuple[Severity, float, list[str]]:
    rule_ids: list[str] = []
    sev_scores: dict[Severity, float] = {s: 0.0 for s in Severity}

    if incident.error_rate is not None:
        for sev in [Severity.P1, Severity.P2, Severity.P3]:
            if incident.error_rate >= thresholds["error_rate"][sev]:
                sev_scores[sev] += 3.0
                rule_ids.append(f"err_rate_{sev.value}")
                break

    if incident.latency_ms is not None:
        for sev in [Severity.P1, Severity.P2, Severity.P3]:
            if incident.latency_ms >= thresholds["latency_ms"][sev]:
                sev_scores[sev] += 3.0
                rule_ids.append(f"latency_{sev.value}")
                break

    title_lower = incident.title.lower()
    if any(w in title_lower for w in ["down", "outage", "offline", "unavailable"]):
        sev_scores[Severity.P1] += 4.0
        rule_ids.append("title_outage")
    if any(w in title_lower for w in ["degrad", "slow", "partial"]):
        sev_scores[Severity.P2] += 3.0
        rule_ids.append("title_degraded")
    if any(w in title_lower for w in ["spike", "anomal"]):
        sev_scores[Severity.P3] += 2.0
        rule_ids.append("title_spike")

    for tag in incident.tags:
        tag_lower = tag.lower()
        if tag_lower == "critical":
            sev_scores[Severity.P1] += 2.0
            rule_ids.append("tag_critical")
        elif tag_lower == "warning":
            sev_scores[Severity.P3] += 1.5
            rule_ids.append("tag_warning")
        elif tag_lower == "info":
            sev_scores[Severity.P4] += 1.5
            rule_ids.append("tag_info")

    if not rule_ids:
        sev_scores[Severity.P4] += 1.0
        rule_ids.append("default_p4")

    best_sev = max(Severity, key=lambda s: sev_scores[s])
    total = sum(sev_scores.values()) or 1.0
    confidence = sev_scores[best_sev] / total
    return best_sev, min(confidence, 1.0), rule_ids

def classify(incident: Incident, thresholds: dict | None = None) -> TriageLabel:
    t = thresholds or DEFAULT_THRESHOLDS
    category, cat_conf = _classify_category(incident)
    severity, sev_conf, rule_ids = _classify_severity(incident, t)
    overall_conf = round((cat_conf * 0.4 + sev_conf * 0.6), 3)
    if overall_conf < t.get("confidence_floor", 0.3):
        severity = Severity.P3
        rule_ids.append("low_conf_fallback")
    reasoning = (
        f"category={category.value}(conf={cat_conf:.2f}), "
        f"severity={severity.value}(conf={sev_conf:.2f}) "
        f"via rules={rule_ids}"
    )
    return TriageLabel(
        severity=severity,
        category=category,
        confidence=overall_conf,
        rule_ids=rule_ids,
        reasoning=reasoning,
    )