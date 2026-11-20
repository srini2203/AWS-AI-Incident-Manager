from __future__ import annotations

import json
from typing import Any, Callable

from strands import tool

from app.diagnostics.alb import ALBDiagnosticsCollector
from app.diagnostics.cloudwatch_logs import CloudWatchLogsCollector
from app.diagnostics.cloudwatch_metrics import CloudWatchMetricsCollector
from app.models import Incident
from app.security.redaction import redact_payload


def build_incident_tools(incident: Incident) -> list[Callable[..., Any]]:
    metrics = CloudWatchMetricsCollector()
    logs = CloudWatchLogsCollector()
    alb = ALBDiagnosticsCollector()

    @tool
    def get_cloudwatch_metrics() -> dict[str, Any]:
        """Retrieve CloudWatch metrics relevant to the current incident resource."""
        result = metrics.collect(incident)
        return redact_payload([item.to_dict() for item in result])

    @tool
    def search_application_logs() -> dict[str, Any]:
        """Search configured application log groups for errors around the incident time."""
        result = logs.collect(incident)
        return redact_payload([item.to_dict() for item in result])

    @tool
    def inspect_load_balancer_targets() -> dict[str, Any]:
        """Inspect Application Load Balancer target health for the current incident."""
        result = alb.collect(incident)
        return redact_payload([item.to_dict() for item in result])

    return [
        get_cloudwatch_metrics,
        search_application_logs,
        inspect_load_balancer_targets,
    ]
