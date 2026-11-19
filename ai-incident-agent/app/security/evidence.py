from __future__ import annotations

import json
from typing import Any

from app.config import (
    BEDROCK_MAX_EVIDENCE_CHARS,
    MAX_LOG_ENTRIES,
    MAX_LOG_ENTRY_LENGTH,
    MAX_METRIC_DATAPOINTS,
)
from app.security.redaction import redact_payload


class EvidenceValidationError(ValueError):
    pass


ALLOWED_EVIDENCE_FIELDS = {
    "metrics",
    "logs",
    "target_health",
    "collected_at",
    "collection_errors",
    "resource_metadata",
}

MAX_COLLECTION_ERRORS = 50
MAX_TARGETS_PER_GROUP = 200
MAX_EVIDENCE_DEPTH = 12


def _serialize(evidence: Any) -> dict[str, Any]:
    if hasattr(evidence, "to_dict"):
        evidence = evidence.to_dict()

    if not isinstance(evidence, dict):
        raise EvidenceValidationError(
            "Incident evidence must be a dictionary or expose to_dict()"
        )

    return dict(evidence)


def _validate_structure(payload: dict[str, Any]) -> None:
    unknown_fields = set(payload) - ALLOWED_EVIDENCE_FIELDS

    if unknown_fields:
        raise EvidenceValidationError(
            "Evidence contains unsupported top-level fields"
        )

    for field_name in (
        "metrics",
        "logs",
        "target_health",
        "collection_errors",
    ):
        value = payload.get(field_name, [])

        if not isinstance(value, list):
            raise EvidenceValidationError(
                f"Evidence field {field_name} must be a list"
            )

    metadata = payload.get("resource_metadata", {})

    if not isinstance(metadata, dict):
        raise EvidenceValidationError(
            "resource_metadata must be an object"
        )


def _bounded_string(
    value: Any,
    maximum_length: int,
) -> str:
    text = str(value)

    if len(text) <= maximum_length:
        return text

    return text[:maximum_length] + " [TRUNCATED]"


def _bound_nested_value(
    value: Any,
    depth: int = 0,
) -> Any:
    if depth > MAX_EVIDENCE_DEPTH:
        return "[MAXIMUM NESTING DEPTH REACHED]"

    if isinstance(value, str):
        return _bounded_string(
            value,
            MAX_LOG_ENTRY_LENGTH,
        )

    if isinstance(value, dict):
        return {
            str(key): _bound_nested_value(
                item,
                depth + 1,
            )
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [
            _bound_nested_value(
                item,
                depth + 1,
            )
            for item in value[:MAX_LOG_ENTRIES]
        ]

    if isinstance(value, tuple):
        return [
            _bound_nested_value(
                item,
                depth + 1,
            )
            for item in value[:MAX_LOG_ENTRIES]
        ]

    if value is None or isinstance(value, (bool, int, float)):
        return value

    return _bounded_string(
        value,
        MAX_LOG_ENTRY_LENGTH,
    )


def _bound_metrics(
    metrics: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    bounded = []

    for metric in metrics:
        if not isinstance(metric, dict):
            continue

        datapoints = metric.get("datapoints") or []

        if not isinstance(datapoints, list):
            datapoints = []

        normalized = dict(metric)
        normalized["datapoints"] = [
            _bound_nested_value(item)
            for item in datapoints[:MAX_METRIC_DATAPOINTS]
            if isinstance(item, dict)
        ]

        bounded.append(normalized)

    return bounded


def _bound_logs(
    logs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    bounded = []

    for log_group in logs:
        if not isinstance(log_group, dict):
            continue

        entries = log_group.get("entries") or []

        if not isinstance(entries, list):
            entries = []

        normalized_entries = []

        for entry in entries[:MAX_LOG_ENTRIES]:
            if not isinstance(entry, dict):
                continue

            normalized_entry = {}

            for key, value in entry.items():
                field_name = str(key)

                if field_name == "@message":
                    normalized_entry[field_name] = _bounded_string(
                        value,
                        MAX_LOG_ENTRY_LENGTH,
                    )
                else:
                    normalized_entry[field_name] = _bound_nested_value(
                        value
                    )

            normalized_entries.append(normalized_entry)

        normalized_group = dict(log_group)
        normalized_group["entries"] = normalized_entries
        normalized_group["truncated"] = (
            bool(log_group.get("truncated"))
            or len(entries) > MAX_LOG_ENTRIES
        )

        bounded.append(normalized_group)

    return bounded


def _bound_target_health(
    target_groups: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    bounded = []

    for target_group in target_groups:
        if not isinstance(target_group, dict):
            continue

        targets = target_group.get("targets") or []

        if not isinstance(targets, list):
            targets = []

        normalized = dict(target_group)
        normalized["targets"] = [
            _bound_nested_value(item)
            for item in targets[:MAX_TARGETS_PER_GROUP]
            if isinstance(item, dict)
        ]

        normalized["truncated"] = (
            bool(target_group.get("truncated"))
            or len(targets) > MAX_TARGETS_PER_GROUP
        )

        bounded.append(normalized)

    return bounded


def _estimate_size(payload: dict[str, Any]) -> int:
    return len(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )
    )


def _trim_evidence(
    payload: dict[str, Any],
    maximum_chars: int,
) -> dict[str, Any]:
    if maximum_chars <= 0:
        raise EvidenceValidationError(
            "Maximum evidence size must be positive"
        )

    if _estimate_size(payload) <= maximum_chars:
        return payload

    for log_group in payload["logs"]:
        entries = log_group["entries"]

        while entries and _estimate_size(payload) > maximum_chars:
            entries.pop()

            log_group["truncated"] = True

    for metric in payload["metrics"]:
        datapoints = metric["datapoints"]

        while datapoints and _estimate_size(payload) > maximum_chars:
            datapoints.pop(0)

            metric["truncated"] = True

    for target_group in payload["target_health"]:
        targets = target_group["targets"]

        while targets and _estimate_size(payload) > maximum_chars:
            targets.pop()

            target_group["truncated"] = True

    while (
        payload["collection_errors"]
        and _estimate_size(payload) > maximum_chars
    ):
        payload["collection_errors"].pop()

    while (
        payload["metrics"]
        and _estimate_size(payload) > maximum_chars
    ):
        payload["metrics"].pop()

    while (
        payload["logs"]
        and _estimate_size(payload) > maximum_chars
    ):
        payload["logs"].pop()

    while (
        payload["target_health"]
        and _estimate_size(payload) > maximum_chars
    ):
        payload["target_health"].pop()

    if _estimate_size(payload) > maximum_chars:
        raise EvidenceValidationError(
            "Evidence metadata exceeds the configured analysis size limit"
        )

    return payload


def prepare_evidence_for_analysis(
    evidence: Any,
    maximum_chars: int = BEDROCK_MAX_EVIDENCE_CHARS,
) -> dict[str, Any]:
    payload = _serialize(evidence)

    _validate_structure(payload)

    payload = {
        "metrics": _bound_metrics(
            payload.get("metrics", [])
        ),
        "logs": _bound_logs(
            payload.get("logs", [])
        ),
        "target_health": _bound_target_health(
            payload.get("target_health", [])
        ),
        "collected_at": _bounded_string(
            payload.get("collected_at", ""),
            100,
        ),
        "collection_errors": [
            _bounded_string(item, 500)
            for item in payload.get("collection_errors", [])[
                :MAX_COLLECTION_ERRORS
            ]
        ],
        "resource_metadata": _bound_nested_value(
            payload.get("resource_metadata", {})
        ),
    }

    sanitized = redact_payload(payload)

    if not isinstance(sanitized, dict):
        raise EvidenceValidationError(
            "Sanitized evidence must be an object"
        )

    sanitized["trust_boundary"] = {
        "resource_metadata": "structured_incident_metadata",
        "metrics": "observed_aws_metric_data",
        "target_health": "observed_aws_target_health",
        "logs": "untrusted_application_log_content",
        "collection_errors": "diagnostic_collection_status",
    }

    return _trim_evidence(
        sanitized,
        maximum_chars,
    )


def validate_evidence(evidence: Any) -> bool:
    payload = _serialize(evidence)
    _validate_structure(payload)
    return True


def sanitize_evidence(
    evidence: Any,
    maximum_chars: int = BEDROCK_MAX_EVIDENCE_CHARS,
) -> dict[str, Any]:
    return prepare_evidence_for_analysis(
        evidence,
        maximum_chars=maximum_chars,
    )