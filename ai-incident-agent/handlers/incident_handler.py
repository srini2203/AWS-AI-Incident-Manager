from __future__ import annotations

import json
import logging
from typing import Any

from app.workflow.orchestrator import (
    IncidentWorkflowOrchestrator,
)
from app.workflow.audit import AuditLogger
from app.security.redaction import redact_payload


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

_orchestrator: IncidentWorkflowOrchestrator | None = None


def get_orchestrator() -> IncidentWorkflowOrchestrator:
    global _orchestrator

    if _orchestrator is None:
        _orchestrator = IncidentWorkflowOrchestrator()

    return _orchestrator


def _correlation_id(
    event: dict[str, Any],
    context: Any,
) -> str:
    event_id = str(event.get("id") or "")

    request_id = str(
        getattr(context, "aws_request_id", "") or ""
    )

    return event_id or request_id or "unknown"


def _safe_log(
    message: str,
    details: dict[str, Any],
) -> None:
    sanitized = redact_payload(details)

    logger.info(
        json.dumps(
            {
                "message": message,
                "details": sanitized,
            },
            ensure_ascii=False,
            default=str,
        )
    )


def lambda_handler(
    event: dict[str, Any],
    context: Any,
) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise ValueError("Lambda event must be a JSON object")

    correlation_id = _correlation_id(event, context)

    request_id = str(
        getattr(context, "aws_request_id", "") or ""
    )

    _safe_log(
        "Incident investigation received",
        {
            "correlation_id": correlation_id,
            "request_id": request_id,
            "event_source": event.get("source", ""),
            "detail_type": event.get("detail-type", ""),
        },
    )

    try:
        orchestrator = get_orchestrator()

        result = orchestrator.investigate(
            event=event,
            correlation_id=correlation_id,
        )

        _safe_log(
            "Incident investigation completed",
            {
                "correlation_id": correlation_id,
                "investigation_id": result.get(
                    "investigation_id",
                    "",
                ),
                "incident_id": (
                    result.get("incident", {}).get("event_id", "")
                ),
                "status": result.get("status", ""),
                "notification": result.get("notification", {}),
            },
        )

        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
            },
            "body": json.dumps(
                redact_payload(result),
                ensure_ascii=False,
                default=str,
            ),
        }

    except Exception as exc:
        _safe_log(
            "Incident investigation failed",
            {
                "correlation_id": correlation_id,
                "request_id": request_id,
                "error_type": type(exc).__name__,
            },
        )

        raise