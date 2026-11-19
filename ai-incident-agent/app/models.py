from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class InvestigationStatus(str, Enum):
    RECEIVED = "RECEIVED"
    COLLECTING = "COLLECTING"
    ANALYZING = "ANALYZING"
    COMPLETED = "COMPLETED"
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
    FAILED = "FAILED"


@dataclass(slots=True)
class Incident:
    alarm_name: str
    severity: str
    resource_id: str
    description: str
    timestamp: str = field(default_factory=utc_now)
    alarm_arn: str = ""
    account_id: str = ""
    region: str = ""
    event_id: str = field(default_factory=lambda: str(uuid4()))
    source: str = "cloudwatch"
    metric_name: str = ""
    metric_namespace: str = ""
    dimensions: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.alarm_name = self._required(self.alarm_name, "alarm_name")
        self.resource_id = self._required(self.resource_id, "resource_id")
        self.severity = self._normalize_severity(self.severity)
        self.description = str(self.description or "").strip()
        self.timestamp = str(self.timestamp or utc_now())
        self.event_id = str(self.event_id or uuid4())
        self.dimensions = {
            str(key): str(value)
            for key, value in self.dimensions.items()
        }

    @staticmethod
    def _required(value: Any, name: str) -> str:
        result = str(value or "").strip()
        if not result:
            raise ValueError(f"{name} is required")
        return result

    @staticmethod
    def _normalize_severity(value: Any) -> str:
        normalized = str(value or "MEDIUM").strip().upper()
        aliases = {
            "P0": "CRITICAL",
            "SEV0": "CRITICAL",
            "P1": "CRITICAL",
            "SEV1": "CRITICAL",
            "P2": "HIGH",
            "SEV2": "HIGH",
            "P3": "MEDIUM",
            "SEV3": "MEDIUM",
            "P4": "LOW",
            "SEV4": "LOW",
            "ALARM": "HIGH",
            "WARNING": "MEDIUM",
            "WARN": "MEDIUM",
            "OK": "INFO",
        }
        normalized = aliases.get(normalized, normalized)
        allowed = {item.value for item in Severity}
        return normalized if normalized in allowed else Severity.MEDIUM.value

    @classmethod
    def from_event(cls, event: dict[str, Any]) -> Incident:
        detail = event.get("detail") or {}
        state = detail.get("state") or {}
        configuration = detail.get("configuration") or {}
        trigger = detail.get("trigger") or {}

        dimensions = {
            str(item["name"]): str(item["value"])
            for item in trigger.get("dimensions", [])
            if item.get("name") and item.get("value") is not None
        }

        alarm_name = str(
            event.get("alarm_name")
            or detail.get("alarmName")
            or detail.get("alarm_name")
            or event.get("detail-type")
            or "UnknownAlarm"
        )

        resources = event.get("resources") or []

        resource_id = (
            event.get("resource_id")
            or detail.get("resource_id")
            or dimensions.get("InstanceId")
            or dimensions.get("DBInstanceIdentifier")
            or dimensions.get("LoadBalancer")
            or dimensions.get("TargetGroup")
            or dimensions.get("FunctionName")
            or (resources[0] if resources else "")
            or alarm_name
        )

        return cls(
            alarm_name=alarm_name,
            severity=str(
                event.get("severity")
                or detail.get("severity")
                or state.get("value")
                or "MEDIUM"
            ),
            resource_id=str(resource_id),
            description=str(
                event.get("description")
                or detail.get("description")
                or configuration.get("description")
                or state.get("reason")
                or "CloudWatch alarm state change"
            ),
            timestamp=str(
                event.get("timestamp")
                or detail.get("time")
                or event.get("time")
                or utc_now()
            ),
            alarm_arn=str(
                detail.get("alarmArn")
                or event.get("alarm_arn")
                or ""
            ),
            account_id=str(
                event.get("account")
                or event.get("account_id")
                or ""
            ),
            region=str(event.get("region") or ""),
            event_id=str(event.get("id") or event.get("event_id") or uuid4()),
            source=str(event.get("source") or "cloudwatch"),
            metric_name=str(trigger.get("metricName") or ""),
            metric_namespace=str(trigger.get("namespace") or ""),
            dimensions=dimensions,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class MetricEvidence:
    namespace: str
    metric_name: str
    dimensions: dict[str, str]
    datapoints: list[dict[str, Any]]
    unit: str = "None"
    period_seconds: int = 60
    statistic: str = "Average"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class LogEvidence:
    log_group: str
    entries: list[dict[str, Any]]
    query: str = ""
    start_time: str = ""
    end_time: str = ""
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class TargetHealthEvidence:
    target_group_arn: str
    targets: list[dict[str, Any]]
    load_balancer_arn: str = ""
    target_count: int = 0
    healthy_count: int = 0
    unhealthy_count: int = 0

    def __post_init__(self) -> None:
        self.target_count = len(self.targets)
        self.healthy_count = sum(
            1
            for target in self.targets
            if str(target.get("TargetHealth", {}).get("State", "")).lower()
            == "healthy"
        )
        self.unhealthy_count = sum(
            1
            for target in self.targets
            if str(target.get("TargetHealth", {}).get("State", "")).lower()
            in {"unhealthy", "unused", "draining"}
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class IncidentEvidence:
    metrics: list[MetricEvidence] = field(default_factory=list)
    logs: list[LogEvidence] = field(default_factory=list)
    target_health: list[TargetHealthEvidence] = field(default_factory=list)
    collected_at: str = field(default_factory=utc_now)
    collection_errors: list[str] = field(default_factory=list)
    resource_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "metrics": [item.to_dict() for item in self.metrics],
            "logs": [item.to_dict() for item in self.logs],
            "target_health": [
                item.to_dict() for item in self.target_health
            ],
            "collected_at": self.collected_at,
            "collection_errors": list(self.collection_errors),
            "resource_metadata": dict(self.resource_metadata),
        }


@dataclass(slots=True)
class IncidentAnalysis:
    summary: str
    probable_root_cause: str
    confidence: float
    impact: str
    recommendations: list[str]
    evidence_references: list[str] = field(default_factory=list)
    requires_human_approval: bool = True
    model_id: str = ""
    generated_at: str = field(default_factory=utc_now)
    guardrail_action: str = "NONE"
    severity: str = "MEDIUM"

    def __post_init__(self) -> None:
        self.confidence = min(1.0, max(0.0, float(self.confidence)))
        self.recommendations = [
            str(item).strip()
            for item in self.recommendations
            if str(item).strip()
        ]
        self.evidence_references = [
            str(item).strip()
            for item in self.evidence_references
            if str(item).strip()
        ]
        self.severity = Incident._normalize_severity(self.severity)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class InvestigationResult:
    incident: Incident
    evidence: IncidentEvidence
    analysis: IncidentAnalysis | None = None
    status: InvestigationStatus = InvestigationStatus.RECEIVED
    investigation_id: str = field(default_factory=lambda: str(uuid4()))
    started_at: str = field(default_factory=utc_now)
    completed_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident": self.incident.to_dict(),
            "evidence": self.evidence.to_dict(),
            "analysis": (
                self.analysis.to_dict()
                if self.analysis is not None
                else None
            ),
            "status": self.status.value,
            "investigation_id": self.investigation_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


@dataclass(slots=True)
class ApprovalRequest:
    approval_id: str
    incident_id: str
    action: str
    requested_by: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: str = field(default_factory=utc_now)
    expires_at: str = ""
    reviewed_by: str = ""
    reviewed_at: str = ""
    review_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["status"] = self.status.value
        return result