from __future__ import annotations

import json
from typing import Any

import boto3
from botocore.config import Config

from app.config import (
    AWS_API_TIMEOUT_SECONDS,
    AWS_REGION,
    APPROVAL_API_URL,
    ENABLE_SNS_NOTIFICATIONS,
    SNS_TOPIC_ARN,
)
from app.models import ApprovalRequest, Incident, IncidentAnalysis, InvestigationResult
from app.security.redaction import redact_payload
from app.workflow.audit import AuditLogger


class SNSNotificationService:
    def __init__(
        self,
        client: Any | None = None,
        topic_arn: str | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.topic_arn = (topic_arn if topic_arn is not None else SNS_TOPIC_ARN).strip()
        self.audit_logger = audit_logger or AuditLogger()
        self.client = client
        if self.client is None and ENABLE_SNS_NOTIFICATIONS and self.topic_arn:
            self.client = boto3.client(
                "sns",
                region_name=AWS_REGION,
                config=Config(
                    connect_timeout=AWS_API_TIMEOUT_SECONDS,
                    read_timeout=AWS_API_TIMEOUT_SECONDS,
                    retries={"max_attempts": 3, "mode": "standard"},
                ),
            )

    @staticmethod
    def _subject(value: str) -> str:
        normalized = " ".join(str(value).split())
        return (normalized or "AWS incident notification")[:100]

    def _publish(self, subject: str, payload: dict[str, Any]) -> dict[str, str]:
        if not ENABLE_SNS_NOTIFICATIONS:
            return {"status": "DISABLED", "message_id": ""}
        if not self.topic_arn:
            return {"status": "NOT_CONFIGURED", "message_id": ""}
        if self.client is None:
            raise RuntimeError("SNS client is not configured")

        safe_payload = redact_payload(payload)
        response = self.client.publish(
            TopicArn=self.topic_arn,
            Subject=self._subject(subject),
            Message=json.dumps(
                safe_payload,
                ensure_ascii=False,
                indent=2,
                default=str,
            ),
        )
        message_id = str(response.get("MessageId", ""))
        result = {"status": "SENT", "message_id": message_id}
        self.audit_logger.emit(
            event_type="SNS_NOTIFICATION_SENT",
            outcome="SENT",
            resource=self.topic_arn,
            details={"message_id": message_id, "subject": subject},
        )
        return result

    @staticmethod
    def _incident_payload(
        incident: Incident,
        analysis: IncidentAnalysis,
        investigation_id: str,
    ) -> dict[str, Any]:
        return {
            "notification_type": "INCIDENT_INVESTIGATION",
            "investigation_id": investigation_id,
            "incident": incident.to_dict(),
            "analysis": analysis.to_dict(),
            "automation_policy": {
                "mode": "READ_ONLY",
                "autonomous_remediation": False,
                "human_approval_required": True,
            },
        }

    def send_investigation_report(
        self,
        result_or_incident: InvestigationResult | Incident,
        analysis: IncidentAnalysis | None = None,
        investigation_id: str = "",
    ) -> dict[str, str]:
        if isinstance(result_or_incident, InvestigationResult):
            incident = result_or_incident.incident
            analysis = result_or_incident.analysis
            investigation_id = result_or_incident.investigation_id
        else:
            incident = result_or_incident

        if not isinstance(incident, Incident):
            raise TypeError("incident must be an Incident instance")
        if not isinstance(analysis, IncidentAnalysis):
            raise ValueError("Incident analysis is required")

        payload = self._incident_payload(
            incident=incident,
            analysis=analysis,
            investigation_id=investigation_id or incident.event_id,
        )
        return self._publish(
            subject=f"[{analysis.severity}] {incident.alarm_name}",
            payload=payload,
        )

    def send_incident_report(
        self,
        incident: Incident,
        analysis: IncidentAnalysis,
        investigation_id: str = "",
    ) -> dict[str, str]:
        return self.send_investigation_report(
            incident,
            analysis,
            investigation_id,
        )

    def send_approval_request(
        self,
        incident: Incident,
        approval: ApprovalRequest,
    ) -> dict[str, str]:
        if not isinstance(incident, Incident):
            raise TypeError("incident must be an Incident instance")
        if not isinstance(approval, ApprovalRequest):
            raise TypeError("approval must be an ApprovalRequest instance")

        return self._publish(
            subject=f"[APPROVAL REQUIRED] {incident.alarm_name}",
            payload={
                "notification_type": "HUMAN_APPROVAL_REQUEST",
                "incident": incident.to_dict(),
                "approval": approval.to_dict(),
                "approval_api": (
                    f"{APPROVAL_API_URL.rstrip('/')}/approvals/{approval.approval_id}"
                    if APPROVAL_API_URL
                    else ""
                ),
                "message": "Review the proposed action. No infrastructure change is executed automatically.",
            },
        )
