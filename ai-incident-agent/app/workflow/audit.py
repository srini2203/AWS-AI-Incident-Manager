from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from app.config import AUDIT_LOG_LEVEL
from app.security.redaction import redact_payload


class AuditLogger:
    def __init__(self, logger: logging.Logger | None = None) -> None:
        self.logger = logger or logging.getLogger("incident_agent.audit")
        self.logger.setLevel(getattr(logging, AUDIT_LOG_LEVEL, logging.INFO))

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()

    def emit(
        self,
        event_type: str,
        actor: str = "incident-triage-agent",
        outcome: str = "INFO",
        resource: str = "",
        incident_id: str = "",
        correlation_id: str = "",
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        event = {
            "timestamp": self._timestamp(),
            "event_type": str(event_type)[:128],
            "actor": str(actor)[:256],
            "outcome": str(outcome)[:64],
            "resource": str(resource)[:512],
            "incident_id": str(incident_id)[:256],
            "correlation_id": str(correlation_id)[:256],
            "details": details or {},
        }
        safe_event = redact_payload(event)
        self.logger.log(
            getattr(logging, AUDIT_LOG_LEVEL, logging.INFO),
            json.dumps(safe_event, ensure_ascii=False, separators=(",", ":"), default=str),
        )
        return safe_event

    def investigation_started(
        self,
        incident_id: str,
        alarm_name: str,
        resource: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        return self.emit(
            event_type="INVESTIGATION_STARTED",
            outcome="STARTED",
            incident_id=incident_id,
            resource=resource,
            correlation_id=correlation_id,
            details={"alarm_name": alarm_name},
        )

    def investigation_completed(
        self,
        incident_id: str,
        status: str,
        confidence: float,
        model_id: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        return self.emit(
            event_type="INVESTIGATION_COMPLETED",
            outcome=status,
            incident_id=incident_id,
            correlation_id=correlation_id,
            details={
                "confidence": max(0.0, min(1.0, float(confidence))),
                "model_id": model_id,
            },
        )

    def approval_decision(
        self,
        approval_id: str,
        incident_id: str,
        actor: str,
        decision: str,
        reason: str = "",
    ) -> dict[str, Any]:
        return self.emit(
            event_type="APPROVAL_DECISION_RECORDED",
            actor=actor,
            outcome=decision,
            resource=approval_id,
            incident_id=incident_id,
            details={"reason": reason},
        )
