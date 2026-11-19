from __future__ import annotations

import json
import os
from typing import Any
from uuid import uuid4

from app.config import APPROVAL_TTL_HOURS
from app.models import (
    ApprovalRequest,
    ApprovalStatus,
    Incident,
    utc_now,
)
from app.storage.approvals import (
    ApprovalRepository,
)
from app.workflow.audit import AuditLogger
from app.workflow.notifications import (
    SNSNotificationService,
)


class ApprovalWorkflowError(RuntimeError):
    pass


class ReviewerAuthenticationError(ApprovalWorkflowError):
    pass


class ReviewerAuthorizationError(ApprovalWorkflowError):
    pass


class ApprovalService:
    def __init__(
        self,
        repository: ApprovalRepository | None = None,
        notification_service: SNSNotificationService | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.repository = repository or ApprovalRepository()
        self.audit_logger = audit_logger or AuditLogger()
        self.notification_service = (
            notification_service
            or SNSNotificationService(
                audit_logger=self.audit_logger
            )
        )

    @staticmethod
    def _validate_action(action: str) -> str:
        normalized = str(action or "").strip()

        if not normalized:
            raise ValueError("Proposed action is required")

        if len(normalized) > 500:
            raise ValueError(
                "Proposed action cannot exceed 500 characters"
            )

        return normalized

    def create_request(
        self,
        incident: Incident,
        action: str,
        requested_by: str = "incident-triage-agent",
    ) -> ApprovalRequest:
        if not isinstance(incident, Incident):
            raise TypeError(
                "incident must be an Incident instance"
            )

        if not requested_by or not requested_by.strip():
            raise ValueError("requested_by is required")

        normalized_action = self._validate_action(action)

        approval = ApprovalRequest(
            approval_id=str(uuid4()),
            incident_id=incident.event_id,
            action=normalized_action,
            requested_by=requested_by.strip(),
            status=ApprovalStatus.PENDING,
        )

        stored_approval = self.repository.create(approval)

        self.audit_logger.emit(
            event_type="APPROVAL_REQUEST_CREATED",
            actor=requested_by.strip(),
            outcome="PENDING",
            resource=stored_approval.approval_id,
            incident_id=incident.event_id,
            details={
                "action": normalized_action,
                "expires_at": stored_approval.expires_at,
            },
        )

        notification_status = "NOT_SENT"

        try:
            result = self.notification_service.send_approval_request(
                incident=incident,
                approval=stored_approval,
            )
            notification_status = result.get(
                "status",
                "UNKNOWN",
            )

        except Exception as exc:
            self.audit_logger.emit(
                event_type="APPROVAL_NOTIFICATION_FAILED",
                actor="incident-triage-agent",
                outcome="FAILED",
                resource=stored_approval.approval_id,
                incident_id=incident.event_id,
                details={
                    "error_type": type(exc).__name__,
                },
            )

        return stored_approval

    def get_request(
        self,
        approval_id: str,
    ) -> ApprovalRequest:
        return self.repository.get(approval_id)

    def decide_request(
        self,
        approval_id: str,
        decision: str,
        reviewer: str,
        reason: str = "",
    ) -> ApprovalRequest:
        if not reviewer or not reviewer.strip():
            raise ReviewerAuthenticationError(
                "Authenticated reviewer identity is required"
            )

        normalized_reviewer = reviewer.strip()
        normalized_reason = str(reason or "").strip()

        if len(normalized_reason) > 2000:
            raise ValueError(
                "Decision reason cannot exceed 2000 characters"
            )

        approval = self.repository.decide(
            approval_id=approval_id,
            decision=decision,
            reviewed_by=normalized_reviewer,
            reason=normalized_reason,
        )

        self.audit_logger.approval_decision(
            approval_id=approval.approval_id,
            incident_id=approval.incident_id,
            actor=normalized_reviewer,
            decision=approval.status.value,
            reason=normalized_reason,
        )

        return approval


def _get_authorizer_context(
    event: dict[str, Any],
) -> dict[str, Any]:
    request_context = event.get("requestContext") or {}

    if not isinstance(request_context, dict):
        raise ReviewerAuthenticationError(
            "Invalid API Gateway request context"
        )

    authorizer = request_context.get("authorizer") or {}

    if not isinstance(authorizer, dict):
        raise ReviewerAuthenticationError(
            "Authenticated authorizer context is missing"
        )

    return authorizer


def resolve_reviewer(
    event: dict[str, Any],
) -> str:
    authorizer = _get_authorizer_context(event)

    jwt_context = authorizer.get("jwt") or {}
    claims = jwt_context.get("claims") or authorizer.get("claims") or {}

    if not isinstance(claims, dict):
        claims = {}

    reviewer = (
        claims.get("cognito:username")
        or claims.get("preferred_username")
        or claims.get("username")
        or claims.get("sub")
        or authorizer.get("principalId")
    )

    if reviewer:
        scopes = jwt_context.get("scopes") or []

        if isinstance(scopes, str):
            scopes = scopes.split()

        groups = claims.get("cognito:groups") or claims.get("groups") or []

        if isinstance(groups, str):
            try:
                groups = json.loads(groups)
            except json.JSONDecodeError:
                groups = [
                    item.strip()
                    for item in groups.split(",")
                    if item.strip()
                ]

        required_groups = {
            item.strip()
            for item in os.getenv(
                "APPROVER_GROUPS",
                "",
            ).split(",")
            if item.strip()
        }

        if required_groups:
            authorized_groups = set(groups or [])

            if not required_groups.intersection(authorized_groups):
                raise ReviewerAuthorizationError(
                    "Reviewer is not a member of an authorized approval group"
                )

        elif "approvals:write" not in scopes:
            if not claims.get("sub"):
                context = authorizer.get("lambda") or {}
                if not context.get("approval_authorized"):
                    raise ReviewerAuthorizationError(
                        "Reviewer lacks approval authorization"
                    )

        return str(reviewer)

    identity = request_context_identity(event)

    if identity:
        return identity

    raise ReviewerAuthenticationError(
        "Unable to identify the authenticated reviewer"
    )


def request_context_identity(
    event: dict[str, Any],
) -> str:
    request_context = event.get("requestContext") or {}
    identity = request_context.get("identity") or {}

    if not isinstance(identity, dict):
        return ""

    user_arn = identity.get("userArn")

    if user_arn:
        return str(user_arn)

    principal_id = identity.get("user")

    if principal_id:
        return str(principal_id)

    return ""


def parse_approval_payload(
    event: dict[str, Any],
) -> tuple[str, str, str]:
    path_parameters = event.get("pathParameters") or {}

    approval_id = str(
        path_parameters.get("approval_id") or ""
    ).strip()

    if not approval_id:
        raise ValueError("approval_id is required")

    raw_body = event.get("body") or "{}"

    if event.get("isBase64Encoded"):
        raise ValueError(
            "Base64 encoded approval bodies are not supported"
        )

    if isinstance(raw_body, str):
        try:
            payload = json.loads(raw_body)
        except json.JSONDecodeError as exc:
            raise ValueError(
                "Approval request contains invalid JSON"
            ) from exc
    else:
        payload = raw_body

    if not isinstance(payload, dict):
        raise ValueError(
            "Approval request body must be a JSON object"
        )

    decision = str(payload.get("decision") or "").strip()
    reason = str(payload.get("reason") or "").strip()

    if decision.upper() not in {
        "APPROVE",
        "APPROVED",
        "REJECT",
        "REJECTED",
    }:
        raise ValueError(
            "Decision must be APPROVE or REJECT"
        )

    return approval_id, decision, reason


def handle_approval_decision(
    event: dict[str, Any],
    service: ApprovalService | None = None,
) -> dict[str, Any]:
    approval_id = ""
    reviewer = ""

    try:
        reviewer = resolve_reviewer(event)

        approval_id, decision, reason = parse_approval_payload(
            event
        )

        approval_service = service or ApprovalService()

        approval = approval_service.decide_request(
            approval_id=approval_id,
            decision=decision,
            reviewer=reviewer,
            reason=reason,
        )

        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "Cache-Control": "no-store",
            },
            "body": json.dumps({
                "approval": approval.to_dict(),
                "message": (
                    "Approval decision recorded. "
                    "No infrastructure remediation was executed."
                ),
            }),
        }

    except ReviewerAuthenticationError as exc:
        status_code = 401
        message = str(exc)

    except ReviewerAuthorizationError as exc:
        status_code = 403
        message = str(exc)

    except ValueError as exc:
        status_code = 400
        message = str(exc)

    except Exception:
        status_code = 500
        message = "Unable to process approval decision"

    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
        },
        "body": json.dumps({
            "error": message,
            "approval_id": approval_id,
        }),
    }


def create_approval_request(
    incident: Incident,
    action: str,
    service: ApprovalService | None = None,
) -> ApprovalRequest:
    approval_service = service or ApprovalService()

    return approval_service.create_request(
        incident=incident,
        action=action,
    )