from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable

from app.config import (
    INVESTIGATION_MAX_CONCURRENCY,
    LOAD_BALANCER_ARN,
    TARGET_GROUP_ARN,
)
from app.diagnostics.alb import ALBDiagnosticsCollector
from app.diagnostics.cloudwatch_logs import CloudWatchLogsCollector
from app.diagnostics.cloudwatch_metrics import CloudWatchMetricsCollector
from app.models import (
    Incident,
    IncidentEvidence,
    LogEvidence,
    MetricEvidence,
    TargetHealthEvidence,
)


class IncidentEvidenceCollector:
    def __init__(
        self,
        metrics_collector: CloudWatchMetricsCollector | None = None,
        logs_collector: CloudWatchLogsCollector | None = None,
        alb_collector: ALBDiagnosticsCollector | None = None,
        metrics_client: Any | None = None,
        logs_client: Any | None = None,
        alb_client: Any | None = None,
        max_concurrency: int = INVESTIGATION_MAX_CONCURRENCY,
    ) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be positive")

        self.metrics_collector = (
            metrics_collector
            or CloudWatchMetricsCollector(client=metrics_client)
        )

        self.logs_collector = (
            logs_collector
            or CloudWatchLogsCollector(client=logs_client)
        )

        self.alb_collector = (
            alb_collector
            or ALBDiagnosticsCollector(client=alb_client)
        )

        self.max_concurrency = max_concurrency

    @staticmethod
    def _is_alb_incident(incident: Incident) -> bool:
        if TARGET_GROUP_ARN or LOAD_BALANCER_ARN:
            return True

        if incident.dimensions.get("TargetGroup"):
            return True

        if incident.dimensions.get("LoadBalancer"):
            return True

        resource_id = incident.resource_id.lower()

        return (
            ":targetgroup/" in resource_id
            or resource_id.startswith("targetgroup/")
            or ":loadbalancer/" in resource_id
            or resource_id.startswith("app/")
            or resource_id.startswith("net/")
        )

    @staticmethod
    def _collect_metrics(
        collector: CloudWatchMetricsCollector,
        incident: Incident,
    ) -> list[MetricEvidence]:
        return collector.collect(incident)

    @staticmethod
    def _collect_logs(
        collector: CloudWatchLogsCollector,
        incident: Incident,
    ) -> list[LogEvidence]:
        return collector.collect(incident)

    @staticmethod
    def _collect_target_health(
        collector: ALBDiagnosticsCollector,
        incident: Incident,
    ) -> list[TargetHealthEvidence]:
        return collector.collect(incident)

    @staticmethod
    def _resource_metadata(
        incident: Incident,
    ) -> dict[str, Any]:
        return {
            "resource_id": incident.resource_id,
            "alarm_name": incident.alarm_name,
            "alarm_arn": incident.alarm_arn,
            "account_id": incident.account_id,
            "region": incident.region,
            "source": incident.source,
            "metric_name": incident.metric_name,
            "metric_namespace": incident.metric_namespace,
            "dimensions": dict(incident.dimensions),
        }

    def collect(self, incident: Incident) -> IncidentEvidence:
        metrics: list[MetricEvidence] = []
        logs: list[LogEvidence] = []
        target_health: list[TargetHealthEvidence] = []
        collection_errors: list[str] = []

        tasks: dict[str, Callable[[], Any]] = {
            "cloudwatch_metrics": lambda: self._collect_metrics(
                self.metrics_collector,
                incident,
            ),
            "cloudwatch_logs": lambda: self._collect_logs(
                self.logs_collector,
                incident,
            ),
        }

        if self._is_alb_incident(incident):
            tasks["alb_target_health"] = lambda: self._collect_target_health(
                self.alb_collector,
                incident,
            )

        task_results: dict[str, Any] = {}

        with ThreadPoolExecutor(
            max_workers=min(
                self.max_concurrency,
                len(tasks),
            )
        ) as executor:
            future_tasks = {
                executor.submit(task): name
                for name, task in tasks.items()
            }

            for future in as_completed(future_tasks):
                task_name = future_tasks[future]

                try:
                    task_results[task_name] = future.result()
                except Exception as exc:
                    collection_errors.append(
                        f"{task_name}: {type(exc).__name__}: {str(exc)[:500]}"
                    )

        metrics = task_results.get("cloudwatch_metrics", [])
        logs = task_results.get("cloudwatch_logs", [])
        target_health = task_results.get("alb_target_health", [])

        completed_collectors = len(task_results)
        failed_collectors = len(collection_errors)

        if failed_collectors == len(tasks):
            collection_errors.append(
                "All AWS evidence collectors failed"
            )

        resource_metadata = self._resource_metadata(incident)

        resource_metadata["diagnostics"] = {
            "collectors_requested": list(tasks.keys()),
            "collectors_completed": completed_collectors,
            "collectors_failed": failed_collectors,
            "evidence_collected": {
                "metrics": len(metrics),
                "log_groups": len(logs),
                "target_groups": len(target_health),
            },
        }

        return IncidentEvidence(
            metrics=metrics,
            logs=logs,
            target_health=target_health,
            collected_at=datetime.now(timezone.utc).isoformat(),
            collection_errors=collection_errors,
            resource_metadata=resource_metadata,
        )


def collect_incident_evidence(
    incident: Incident,
    metrics_client: Any | None = None,
    logs_client: Any | None = None,
    alb_client: Any | None = None,
) -> IncidentEvidence:
    collector = IncidentEvidenceCollector(
        metrics_client=metrics_client,
        logs_client=logs_client,
        alb_client=alb_client,
    )

    return collector.collect(incident)