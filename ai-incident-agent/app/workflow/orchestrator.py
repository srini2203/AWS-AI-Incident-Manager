from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.analysis.analyzer import IncidentAnalyzer
from app.diagnostics.collector import IncidentEvidenceCollector
from app.event_parser import parse_event
from app.models import (
    ApprovalRequest,
    Incident,
    InvestigationResult,
    InvestigationStatus,
)
from app.workflow.approval import ApprovalService
from app.workflow.audit import AuditLogger
from app.workflow.notifications import SNSNotificationService


class InvestigationError(RuntimeError):
    pass


class IncidentWorkflowOrchestrator:
    def __init__(
        self,
        evidence_collector: IncidentEvidenceCollector | None = None,
        analyzer: IncidentAnalyzer | None = None,
        notification_service: SNSNotificationService | None = None,
        approval_service: ApprovalService | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.audit_logger = audit_logger or AuditLogger()

        self.evidence_collector = (
            evidence_collector
            or IncidentEvidenceCollector()
        )

        self.analyzer = analyzer or IncidentAnalyzer()

        self.notification_service = (
            notification_service
            or SNSNotificationService(
                audit_logger=self.audit_logger
            )
        )

        self.approval_service = (
            approval_service
            or ApprovalService(
                notification_service=self.notification_service,
                audit_logger=self.audit_logger,
            )
        )

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _notification_result(
        status: str,
        message_id: str = "",
    ) -> dict[str, str]:
        return {
            "status": status,
            "message_id": message_id,
        }

    def _audit_start(
        self,
        incident: Incident,
        correlation_id: str,
    ) -> None:
        self.audit_logger.investigation_started(
            incident_id=incident.event_id,
            alarm_name=incident.alarm_name,
            resource=incident.resource_id,
            correlation_id=correlation_id,
        )

    def _audit_failure(
        self,
        incident: Incident,
        correlation_id: str,
        error: Exception,
    ) -> None:
        self.audit_logger.emit(
            event_type="INVESTIGATION_FAILED",
            actor="incident-triage-agent",
            outcome="FAILED",
            resource=incident.resource_id,
            incident_id=incident.event_id,
            correlation_id=correlation_id,
            details={
                "error_type": type(error).__name__,
            },
        )

    def _send_report(
        self,
        result: InvestigationResult,
        correlation_id: str,
    ) -> dict[str, str]:
        if result.analysis is None:
            return self._notification_result(
                "SKIPPED"
            )

        try:
            response = self.notification_service.send_investigation_report(
                result
            )

            return self._notification_result(
                response.get("status", "UNKNOWN"),
                response.get("message_id", ""),
            )

        except Exception as exc:
            self.audit_logger.emit(
                event_type="INCIDENT_REPORT_NOTIFICATION_FAILED",
                actor="incident-triage-agent",
                outcome="FAILED",
                resource=result.incident.resource_id,
                incident_id=result.incident.event_id,
                correlation_id=correlation_id,
                details={
                    "error_type": type(exc).__name__,
                },
            )

            return self._notification_result(
                "FAILED"
            )

    def investigate(
        self,
        event: dict[str, Any] | str | bytes,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        incident = parse_event(event)

        investigation_id = str(uuid4())
        correlation_id = correlation_id or investigation_id
        started_at = self._now()

        self._audit_start(
            incident=incident,
            correlation_id=correlation_id,
        )

        try:
            evidence = self.evidence_collector.collect(
                incident
            )

        except Exception as exc:
            self._audit_failure(
                incident=incident,
                correlation_id=correlation_id,
                error=exc,
            )

            raise InvestigationError(
                "AWS incident evidence collection failed"
            ) from exc

        result = InvestigationResult(
            incident=incident,
            evidence=evidence,
            analysis=None,
            status=InvestigationStatus.ANALYZING,
            investigation_id=investigation_id,
            started_at=started_at,
        )

        try:
            analysis = self.analyzer.analyze(
                incident=incident,
                evidence=evidence,
            )

        except Exception as exc:
            evidence.collection_errors.append(
                f"Bedrock analysis failed: {type(exc).__name__}"
            )

            result.status = InvestigationStatus.FAILED
            result.completed_at = self._now()

            self._audit_failure(
                incident=incident,
                correlation_id=correlation_id,
                error=exc,
            )

            raise InvestigationError(
                "Amazon Bedrock incident analysis failed"
            ) from exc

        result.analysis = analysis

        if evidence.collection_errors:
            result.status = InvestigationStatus.PARTIALLY_COMPLETED
        else:
            result.status = InvestigationStatus.COMPLETED

        result.completed_at = self._now()

        self.audit_logger.investigation_completed(
            incident_id=incident.event_id,
            status=result.status.value,
            confidence=analysis.confidence,
            model_id=analysis.model_id,
            correlation_id=correlation_id,
        )

        notification = self._send_report(
            result=result,
            correlation_id=correlation_id,
        )

        return {
            **result.to_dict(),
            "notification": notification,
            "automation_policy": {
                "mode": "READ_ONLY",
                "autonomous_remediation": False,
                "human_approval_required": True,
            },
        }

    def request_approval(
        self,
        incident: Incident,
        action: str,
        requested_by: str = "incident-triage-agent",
    ) -> ApprovalRequest:
        if not isinstance(incident, Incident):
            raise TypeError(
                "incident must be an Incident instance"
            )

        approval = self.approval_service.create_request(
            incident=incident,
            action=action,
            requested_by=requested_by,
        )

        self.audit_logger.emit(
            event_type="REMEDIATION_APPROVAL_REQUESTED",
            actor=requested_by,
            outcome="PENDING",
            resource=approval.approval_id,
            incident_id=incident.event_id,
            details={
                "action": approval.action,
                "expires_at": approval.expires_at,
            },
        )

        return approval


def investigate_incident(
    event: dict[str, Any] | str | bytes,
    evidence_collector: IncidentEvidenceCollector | None = None,
    analyzer: IncidentAnalyzer | None = None,
    notification_service: SNSNotificationService | None = None,
    approval_service: ApprovalService | None = None,
    audit_logger: AuditLogger | None = None,
) -> dict[str, Any]:
    orchestrator = IncidentWorkflowOrchestrator(
        evidence_collector=evidence_collector,
        analyzer=analyzer,
        notification_service=notification_service,
        approval_service=approval_service,
        audit_logger=audit_logger,
    )

    return orchestrator.investigate(event)