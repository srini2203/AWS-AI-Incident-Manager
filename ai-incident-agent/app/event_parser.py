from __future__ import annotations

import json
from typing import Any

from app.models import Incident


def _decode_payload(value: Any) -> Any:
    if isinstance(value, bytes):
        value = value.decode("utf-8")

    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError("Event payload contains invalid JSON") from exc

    return value


def _extract_sns_message(record: dict[str, Any]) -> Any:
    sns = record.get("Sns") or record.get("sns") or {}
    message = sns.get("Message") or sns.get("message")

    if message is None:
        raise ValueError("SNS record does not contain a message")

    return _decode_payload(message)


def _normalize_payload(event: Any) -> dict[str, Any]:
    payload = _decode_payload(event)

    if not isinstance(payload, dict):
        raise ValueError("Event payload must be a JSON object")

    if "body" in payload and payload["body"] is not None:
        return _normalize_payload(payload["body"])

    if payload.get("Type") == "Notification" or payload.get("type") == "notification":
        return _normalize_payload(
            payload.get("Message") or payload.get("message")
        )

    if "Records" in payload:
        records = payload["Records"]

        if not isinstance(records, list) or len(records) != 1:
            raise ValueError(
                "A single record is required by parse_event; use parse_events for batches"
            )

        record = records[0]

        if not isinstance(record, dict):
            raise ValueError("Event record must be an object")

        if "Sns" in record or record.get("EventSource") == "aws:sns":
            return _normalize_payload(_extract_sns_message(record))

        if record.get("eventSource") == "aws:sqs":
            body = record.get("body")

            if body is None:
                raise ValueError("SQS record does not contain a body")

            return _normalize_payload(body)

        raise ValueError("Unsupported event record type")

    if "Message" in payload and isinstance(payload["Message"], str):
        return _normalize_payload(payload["Message"])

    return payload


def _extract_dimensions(detail: dict[str, Any]) -> dict[str, str]:
    dimensions: dict[str, str] = {}

    trigger = (
        detail.get("trigger")
        or detail.get("Trigger")
        or {}
    )

    for dimension in trigger.get("dimensions") or trigger.get("Dimensions") or []:
        name = dimension.get("name") or dimension.get("Name")
        value = dimension.get("value") or dimension.get("Value")

        if name and value is not None:
            dimensions[str(name)] = str(value)

    configuration = detail.get("configuration") or {}

    for metric in configuration.get("metrics") or []:
        metric_stat = metric.get("metricStat") or {}
        metric_data = metric_stat.get("metric") or {}

        for dimension in metric_data.get("dimensions") or []:
            name = dimension.get("name")
            value = dimension.get("value")

            if name and value is not None:
                dimensions.setdefault(str(name), str(value))

    return dimensions


def _extract_metric(detail: dict[str, Any]) -> tuple[str, str]:
    trigger = (
        detail.get("trigger")
        or detail.get("Trigger")
        or {}
    )

    namespace = str(
        trigger.get("namespace")
        or trigger.get("Namespace")
        or ""
    )

    metric_name = str(
        trigger.get("metricName")
        or trigger.get("MetricName")
        or ""
    )

    if namespace and metric_name:
        return namespace, metric_name

    configuration = detail.get("configuration") or {}

    for metric in configuration.get("metrics") or []:
        metric_stat = metric.get("metricStat") or {}
        metric_data = metric_stat.get("metric") or {}

        candidate_namespace = metric_data.get("namespace")
        candidate_name = metric_data.get("name")

        if candidate_namespace or candidate_name:
            return (
                str(candidate_namespace or ""),
                str(candidate_name or ""),
            )

    return namespace, metric_name


def _extract_alarm_details(
    payload: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], str]:
    detail = payload.get("detail")

    if isinstance(detail, dict):
        state = detail.get("state") or {}
        return detail, state, "eventbridge"

    if "AlarmName" in payload or "NewStateValue" in payload:
        state = {
            "value": payload.get("NewStateValue"),
            "reason": payload.get("NewStateReason"),
            "timestamp": payload.get("StateChangeTime"),
        }

        detail = {
            "alarmName": payload.get("AlarmName"),
            "alarmArn": payload.get("AlarmArn"),
            "state": state,
            "configuration": {
                "description": payload.get("AlarmDescription", ""),
            },
            "trigger": payload.get("Trigger") or {},
        }

        return detail, state, "sns-cloudwatch"

    detail = payload
    state = detail.get("state") or {}
    return detail, state, str(payload.get("source") or "direct")


def _derive_severity(
    explicit_severity: Any,
    alarm_name: str,
    state_value: str,
) -> str:
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
        "WARNING": "MEDIUM",
        "WARN": "MEDIUM",
        "ALARM": "HIGH",
        "OK": "INFO",
        "INSUFFICIENT_DATA": "MEDIUM",
    }

    if explicit_severity:
        value = str(explicit_severity).strip().upper()
        return aliases.get(value, value)

    normalized_name = alarm_name.upper()

    if any(
        marker in normalized_name
        for marker in ("CRITICAL", "SEV1", "P1")
    ):
        return "CRITICAL"

    if any(
        marker in normalized_name
        for marker in ("HIGH", "SEV2", "P2")
    ):
        return "HIGH"

    if any(
        marker in normalized_name
        for marker in ("LOW", "SEV4", "P4")
    ):
        return "LOW"

    if state_value == "OK":
        return "INFO"

    if state_value == "INSUFFICIENT_DATA":
        return "MEDIUM"

    return "HIGH" if state_value == "ALARM" else "MEDIUM"


def _extract_resource_id(
    payload: dict[str, Any],
    detail: dict[str, Any],
    dimensions: dict[str, str],
    alarm_name: str,
) -> str:
    explicit = (
        payload.get("resource_id")
        or detail.get("resource_id")
        or detail.get("resourceId")
    )

    if explicit:
        return str(explicit)

    resource_dimensions = (
        "InstanceId",
        "DBInstanceIdentifier",
        "FunctionName",
        "LoadBalancer",
        "TargetGroup",
        "ClusterName",
        "ServiceName",
        "ResourceId",
    )

    for dimension in resource_dimensions:
        if dimensions.get(dimension):
            return dimensions[dimension]

    if dimensions:
        return next(iter(dimensions.values()))

    resources = payload.get("resources") or []

    for resource in resources:
        if resource:
            return str(resource)

    return alarm_name


def parse_event(event: dict[str, Any] | str | bytes) -> Incident:
    payload = _normalize_payload(event)

    detail, state, source = _extract_alarm_details(payload)

    configuration = detail.get("configuration") or {}

    alarm_name = str(
        payload.get("alarm_name")
        or detail.get("alarmName")
        or detail.get("alarm_name")
        or payload.get("detail-type")
        or "UnknownAlarm"
    )

    dimensions = _extract_dimensions(detail)

    resource_id = _extract_resource_id(
        payload,
        detail,
        dimensions,
        alarm_name,
    )

    state_value = str(
        state.get("value")
        or detail.get("NewStateValue")
        or "ALARM"
    ).upper()

    severity = _derive_severity(
        payload.get("severity") or detail.get("severity"),
        alarm_name,
        state_value,
    )

    description = str(
        payload.get("description")
        or detail.get("description")
        or configuration.get("description")
        or state.get("reason")
        or detail.get("NewStateReason")
        or "CloudWatch alarm state change"
    )

    metric_namespace, metric_name = _extract_metric(detail)

    timestamp = str(
        payload.get("timestamp")
        or detail.get("time")
        or state.get("timestamp")
        or detail.get("StateChangeTime")
        or payload.get("time")
        or ""
    )

    resources = payload.get("resources") or []

    alarm_arn = str(
        detail.get("alarmArn")
        or detail.get("AlarmArn")
        or payload.get("alarm_arn")
        or next(
            (
                resource
                for resource in resources
                if str(resource).startswith("arn:")
            ),
            "",
        )
    )

    return Incident(
        alarm_name=alarm_name,
        severity=severity,
        resource_id=resource_id,
        description=description,
        timestamp=timestamp,
        alarm_arn=alarm_arn,
        account_id=str(
            payload.get("account")
            or payload.get("account_id")
            or ""
        ),
        region=str(payload.get("region") or ""),
        event_id=str(payload.get("id") or payload.get("event_id") or ""),
        source=source,
        metric_name=metric_name,
        metric_namespace=metric_namespace,
        dimensions=dimensions,
    )


def parse_events(
    event: dict[str, Any] | list[Any] | str | bytes,
) -> list[Incident]:
    payload = _decode_payload(event)

    if isinstance(payload, list):
        return [parse_event(item) for item in payload]

    if not isinstance(payload, dict):
        raise ValueError("Event batch must be a JSON object or list")

    records = payload.get("Records")

    if isinstance(records, list):
        incidents = []

        for record in records:
            incidents.append(
                parse_event({"Records": [record]})
            )

        return incidents

    return [parse_event(payload)]