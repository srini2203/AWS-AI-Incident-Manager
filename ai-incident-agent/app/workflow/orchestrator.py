from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.analysis.analyzer import IncidentAnalyzer
from app.config import ANALYZER_MODE, DIAGNOSTICS_MODE
from app.diagnostics.collector import IncidentEvidenceCollector
from app.diagnostics.mock import MockIncidentEvidenceCollector
from app.event_parser import parse_event
from app.models import ApprovalRequest, Incident, InvestigationResult, InvestigationStatus
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
        incident_agent: Any | None = None,
    ) -> None:
        self.audit_logger = audit_logger or AuditLogger()
        self.evidence_collector = evidence_collector or (
            MockIncidentEvidenceCollector() if DIAGNOSTICS_MODE == "mock"
            else IncidentEvidenceCollector()
        )
        self.analyzer = analyzer or (
            IncidentAnalyzer(mode=ANALYZER_MODE)
            if ANALYZER_MODE != "strands" else None
        )
        self.incident_agent = incident_agent
        self.notification_service = notification_service or SNSNotificationService(audit_logger=self.audit_logger)
        self.approval_service = approval_service

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _notification_result(status: str, message_id: str = "") -> dict[str, str]:
        return {"status": status, "message_id": message_id}

    def _audit_start(self, incident: Incident, correlation_id: str) -> None:
        self.audit_logger.investigation_started(
            incident_id=incident.event_id, alarm_name=incident.alarm_name,
            resource=incident.resource_id, correlation_id=correlation_id,
        )

    def _audit_failure(self, incident: Incident, correlation_id: str, error: Exception) -> None:
        self.audit_logger.emit(
            event_type="INVESTIGATION_FAILED", actor="incident-triage-agent",
            outcome="FAILED", resource=incident.resource_id,
            incident_id=incident.event_id, correlation_id=correlation_id,
            details={"error_type": type(error).__name__},
        )

    def _send_report(self, result: InvestigationResult, correlation_id: str) -> dict[str, str]:
        if result.analysis is None:
            return self._notification_result("SKIPPED")
        try:
            response = self.notification_service.send_investigation_report(result)
            return self._notification_result(response.get("status", "UNKNOWN"), response.get("message_id", ""))
        except Exception as exc:
            self.audit_logger.emit(
                event_type="INCIDENT_REPORT_NOTIFICATION_FAILED",
                actor="incident-triage-agent", outcome="FAILED",
                resource=result.incident.resource_id, incident_id=result.incident.event_id,
                correlation_id=correlation_id, details={"error_type": type(exc).__name__},
            )
            return self._notification_result("FAILED")

    def investigate(self, event: dict[str, Any] | str | bytes, correlation_id: str | None = None) -> dict[str, Any]:
        incident = parse_event(event)
        investigation_id = str(uuid4())
        correlation_id = correlation_id or investigation_id
        started_at = self._now()
        self._audit_start(incident, correlation_id)

        try:
            evidence = self.evidence_collector.collect(incident)
        except Exception as exc:
            self._audit_failure(incident, correlation_id, exc)
            raise InvestigationError("AWS incident evidence collection failed") from exc

        result = InvestigationResult(
            incident=incident, evidence=evidence, analysis=None,
            status=InvestigationStatus.ANALYZING, investigation_id=investigation_id,
            started_at=started_at,
        )
        try:
            if ANALYZER_MODE == "strands":
                if self.incident_agent is None:
                    from app.agent.incident_agent import run_incident_agent
                    agent_runner = run_incident_agent
                else:
                    agent_runner = self.incident_agent
                analysis = agent_runner(incident, evidence)
            else:
                if self.analyzer is None:
                    raise RuntimeError("Incident analyzer is not configured")
                analysis = self.analyzer.analyze(incident=incident, evidence=evidence)
        except Exception as exc:
            evidence.collection_errors.append(f"Incident analysis failed: {type(exc).__name__}")
            result.status = InvestigationStatus.FAILED
            result.completed_at = self._now()
            self._audit_failure(incident, correlation_id, exc)
            raise InvestigationError("Incident analysis failed") from exc

        result.analysis = analysis
        result.status = InvestigationStatus.PARTIALLY_COMPLETED if evidence.collection_errors else InvestigationStatus.COMPLETED
        result.completed_at = self._now()
        self.audit_logger.investigation_completed(
            incident_id=incident.event_id, status=result.status.value,
            confidence=analysis.confidence, model_id=analysis.model_id,
            correlation_id=correlation_id,
        )
        notification = self._send_report(result, correlation_id)
        return {
            **result.to_dict(),
            "notification": notification,
            "automation_policy": {
                "mode": "READ_ONLY",
                "autonomous_remediation": False,
                "human_approval_required": True,
            },
        }

    def request_approval(self, incident: Incident, action: str, requested_by: str = "incident-triage-agent") -> ApprovalRequest:
        if not isinstance(incident, Incident):
            raise TypeError("incident must be an Incident instance")
        if self.approval_service is None:
            raise RuntimeError("ApprovalService is not configured")
        approval = self.approval_service.create_request(incident=incident, action=action, requested_by=requested_by)
        self.audit_logger.emit(
            event_type="REMEDIATION_APPROVAL_REQUESTED", actor=requested_by,
            outcome="PENDING", resource=approval.approval_id, incident_id=incident.event_id,
            details={"action": approval.action, "expires_at": approval.expires_at},
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
        evidence_collector=evidence_collector, analyzer=analyzer,
        notification_service=notification_service, approval_service=approval_service,
        audit_logger=audit_logger,
    )
    return orchestrator.investigate(event)
