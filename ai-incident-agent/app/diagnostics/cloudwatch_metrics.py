from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from botocore.config import Config

from app.config import (
    AWS_API_TIMEOUT_SECONDS,
    AWS_REGION,
    MAX_METRIC_DATAPOINTS,
    METRIC_PERIOD_SECONDS,
    METRICS_LOOKBACK_MINUTES,
)
from app.models import Incident, MetricEvidence


METRIC_CATALOG: dict[str, dict[str, list[tuple[str, list[str], str]]]] = {
    "AWS/EC2": {
        "InstanceId": [
            ("CPUUtilization", ["Average", "Maximum"], "Percent"),
            ("NetworkIn", ["Average", "Maximum"], "Bytes"),
            ("NetworkOut", ["Average", "Maximum"], "Bytes"),
            ("StatusCheckFailed", ["Maximum"], "Count"),
            ("StatusCheckFailed_Instance", ["Maximum"], "Count"),
            ("StatusCheckFailed_System", ["Maximum"], "Count"),
        ]
    },
    "AWS/RDS": {
        "DBInstanceIdentifier": [
            ("CPUUtilization", ["Average", "Maximum"], "Percent"),
            ("DatabaseConnections", ["Average", "Maximum"], "Count"),
            ("FreeableMemory", ["Average", "Minimum"], "Bytes"),
            ("FreeStorageSpace", ["Average", "Minimum"], "Bytes"),
            ("ReadLatency", ["Average", "Maximum"], "Seconds"),
            ("WriteLatency", ["Average", "Maximum"], "Seconds"),
            ("ReadIOPS", ["Average", "Maximum"], "Count/Second"),
            ("WriteIOPS", ["Average", "Maximum"], "Count/Second"),
        ]
    },
    "AWS/ApplicationELB": {
        "LoadBalancer": [
            ("RequestCount", ["Sum"], "Count"),
            ("TargetResponseTime", ["Average", "Maximum"], "Seconds"),
            ("HTTPCode_ELB_5XX_Count", ["Sum"], "Count"),
            ("HTTPCode_ELB_4XX_Count", ["Sum"], "Count"),
            ("HealthyHostCount", ["Average", "Minimum"], "Count"),
            ("UnHealthyHostCount", ["Average", "Maximum"], "Count"),
        ]
    },
    "AWS/Lambda": {
        "FunctionName": [
            ("Errors", ["Sum"], "Count"),
            ("Throttles", ["Sum"], "Count"),
            ("Duration", ["Average", "Maximum"], "Milliseconds"),
            ("Invocations", ["Sum"], "Count"),
            ("ConcurrentExecutions", ["Maximum"], "Count"),
        ]
    },
}


class CloudWatchMetricsCollector:
    def __init__(
        self,
        client: Any | None = None,
        region_name: str | None = None,
    ) -> None:
        self.client = client or boto3.client(
            "cloudwatch",
            region_name=region_name or AWS_REGION,
            config=Config(
                connect_timeout=AWS_API_TIMEOUT_SECONDS,
                read_timeout=AWS_API_TIMEOUT_SECONDS,
                retries={
                    "max_attempts": 3,
                    "mode": "standard",
                },
            ),
        )

    @staticmethod
    def _parse_timestamp(value: str) -> datetime:
        if not value:
            return datetime.now(timezone.utc)

        try:
            parsed = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )

            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)

            return parsed.astimezone(timezone.utc)

        except (ValueError, TypeError):
            return datetime.now(timezone.utc)

    @staticmethod
    def _extract_dimension_value(
        incident: Incident,
        dimension_name: str,
    ) -> str | None:
        value = incident.dimensions.get(dimension_name)

        if value:
            return value

        resource_id = incident.resource_id

        if dimension_name == "InstanceId":
            if resource_id.startswith("i-"):
                return resource_id

        if dimension_name == "DBInstanceIdentifier":
            if not resource_id.startswith("arn:"):
                return resource_id

        if dimension_name == "FunctionName":
            if not resource_id.startswith("arn:"):
                return resource_id

            if ":function:" in resource_id:
                return resource_id.split(":function:", 1)[1].split(":")[0]

        if dimension_name == "LoadBalancer":
            if resource_id.startswith("app/") or resource_id.startswith("net/"):
                return resource_id

            if ":loadbalancer/" in resource_id:
                return resource_id.split(":loadbalancer/", 1)[1]

        if dimension_name == "TargetGroup":
            if resource_id.startswith("targetgroup/"):
                return resource_id

            if ":targetgroup/" in resource_id:
                return resource_id.split(":targetgroup/", 1)[1]

        return None

    def _resolve_dimensions(
        self,
        incident: Incident,
        namespace: str,
    ) -> dict[str, str]:
        if namespace not in METRIC_CATALOG:
            return {
                str(key): str(value)
                for key, value in incident.dimensions.items()
            }

        resolved: dict[str, str] = {}

        dimension_names = list(
            METRIC_CATALOG[namespace].keys()
        )

        if namespace == "AWS/ApplicationELB":
            dimension_names.append("TargetGroup")

        for dimension_name in dimension_names:
            value = self._extract_dimension_value(
                incident,
                dimension_name,
            )

            if value:
                resolved[dimension_name] = value

        return resolved

    @staticmethod
    def _metric_definitions(
        incident: Incident,
    ) -> list[tuple[str, list[str], str, str, dict[str, str]]]:
        definitions: list[
            tuple[str, list[str], str, str, dict[str, str]]
        ] = []

        namespace = incident.metric_namespace
        metric_name = incident.metric_name

        dimensions = (
            incident.dimensions.copy()
            if incident.dimensions
            else {}
        )

        if namespace and metric_name:
            definitions.append(
                (
                    namespace,
                    metric_name,
                    ["Average", "Maximum", "Minimum", "Sum"],
                    "None",
                    dimensions,
                )
            )

        if namespace not in METRIC_CATALOG:
            return definitions

        resource_dimensions = METRIC_CATALOG[namespace]

        resolved_dimensions = CloudWatchMetricsCollector(
            client=object()
        )._resolve_dimensions(incident, namespace)

        for dimension_name, metrics in resource_dimensions.items():
            dimension_value = resolved_dimensions.get(dimension_name)

            if not dimension_value:
                continue

            metric_dimensions = {
                dimension_name: dimension_value
            }

            if namespace == "AWS/ApplicationELB":
                target_group = resolved_dimensions.get("TargetGroup")

                if target_group:
                    metric_dimensions["TargetGroup"] = target_group

            for name, statistics, unit in metrics:
                definitions.append(
                    (
                        namespace,
                        name,
                        statistics,
                        unit,
                        metric_dimensions,
                    )
                )

        unique: dict[
            tuple[str, str, tuple[tuple[str, str], ...]],
            tuple[str, str, list[str], str, dict[str, str]],
        ] = {}

        for definition in definitions:
            metric_namespace, name, statistics, unit, metric_dimensions = definition

            key = (
                metric_namespace,
                name,
                tuple(sorted(metric_dimensions.items())),
            )

            unique[key] = definition

        return list(unique.values())

    @staticmethod
    def _serialize_datapoint(
        datapoint: dict[str, Any],
    ) -> dict[str, Any]:
        serialized: dict[str, Any] = {}

        timestamp = datapoint.get("Timestamp")

        if isinstance(timestamp, datetime):
            serialized["timestamp"] = timestamp.astimezone(
                timezone.utc
            ).isoformat()

        for key in (
            "Average",
            "Maximum",
            "Minimum",
            "Sum",
            "SampleCount",
            "Unit",
        ):
            if key in datapoint:
                serialized[key.lower()] = datapoint[key]

        return serialized

    def _collect_metric(
        self,
        namespace: str,
        metric_name: str,
        statistics: list[str],
        unit: str,
        dimensions: dict[str, str],
        start_time: datetime,
        end_time: datetime,
    ) -> MetricEvidence:
        response = self.client.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[
                {
                    "Name": name,
                    "Value": value,
                }
                for name, value in sorted(dimensions.items())
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=METRIC_PERIOD_SECONDS,
            Statistics=statistics,
        )

        datapoints = [
            self._serialize_datapoint(item)
            for item in response.get("Datapoints", [])
        ]

        datapoints.sort(
            key=lambda item: item.get("timestamp", "")
        )

        if len(datapoints) > MAX_METRIC_DATAPOINTS:
            datapoints = datapoints[-MAX_METRIC_DATAPOINTS:]

        return MetricEvidence(
            namespace=namespace,
            metric_name=metric_name,
            dimensions=dimensions,
            datapoints=datapoints,
            unit=unit,
            period_seconds=METRIC_PERIOD_SECONDS,
            statistic=",".join(statistics),
        )

    def collect(
        self,
        incident: Incident,
    ) -> list[MetricEvidence]:
        definitions = self._metric_definitions(incident)

        incident_time = self._parse_timestamp(
            incident.timestamp
        )

        end_time = incident_time + timedelta(
            seconds=METRIC_PERIOD_SECONDS
        )

        start_time = incident_time - timedelta(
            minutes=METRICS_LOOKBACK_MINUTES
        )

        now = datetime.now(timezone.utc)

        if end_time > now:
            end_time = now

        if start_time >= end_time:
            start_time = end_time - timedelta(
                minutes=METRICS_LOOKBACK_MINUTES
            )

        evidence: list[MetricEvidence] = []
        collection_errors: list[str] = []

        for (
            namespace,
            metric_name,
            statistics,
            unit,
            dimensions,
        ) in definitions:
            try:
                if namespace in METRIC_CATALOG and not dimensions:
                    continue

                metric_evidence = self._collect_metric(
                    namespace=namespace,
                    metric_name=metric_name,
                    statistics=statistics,
                    unit=unit,
                    dimensions=dimensions,
                    start_time=start_time,
                    end_time=end_time,
                )

                evidence.append(metric_evidence)

            except Exception as exc:
                collection_errors.append(
                    f"{namespace}/{metric_name}: {type(exc).__name__}"
                )

        if collection_errors and not evidence:
            raise RuntimeError(
                "CloudWatch metric collection failed: "
                + "; ".join(collection_errors)
            )

        return evidence


def collect_metrics(
    incident: Incident,
    client: Any | None = None,
) -> list[MetricEvidence]:
    collector = CloudWatchMetricsCollector(client=client)
    return collector.collect(incident)