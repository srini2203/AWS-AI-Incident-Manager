from __future__ import annotations

import json
import logging
from typing import Any

from app.workflow.approval import handle_approval_decision


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def _get_http_method(event: dict[str, Any]) -> str:
    request_context = event.get("requestContext") or {}
    http_context = request_context.get("http") or {}

    return str(
        http_context.get("method")
        or event.get("httpMethod")
        or ""
    ).upper()


def _response(
    status_code: int,
    body: dict[str, Any],
) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
        "body": json.dumps(
            body,
            ensure_ascii=False,
            default=str,
        ),
    }


def lambda_handler(
    event: dict[str, Any],
    context: Any,
) -> dict[str, Any]:
    if not isinstance(event, dict):
        return _response(
            400,
            {"error": "Request must be a JSON object"},
        )

    request_id = str(
        getattr(context, "aws_request_id", "") or ""
    )

    method = _get_http_method(event)

    if method != "POST":
        return _response(
            405,
            {
                "error": "Method not allowed",
                "allowed_methods": ["POST"],
            },
        )

    try:
        result = handle_approval_decision(event)

        logger.info(
            json.dumps({
                "event_type": "APPROVAL_HANDLER_COMPLETED",
                "request_id": request_id,
                "status_code": result.get("statusCode", 500),
            })
        )

        return result

    except Exception as exc:
        logger.error(
            json.dumps({
                "event_type": "APPROVAL_HANDLER_FAILED",
                "request_id": request_id,
                "error_type": type(exc).__name__,
            })
        )

        return _response(
            500,
            {"error": "Unable to process approval request"},
        )