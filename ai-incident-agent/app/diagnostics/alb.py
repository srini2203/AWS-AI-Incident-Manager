from __future__ import annotations

from typing import Any

import boto3
from botocore.config import Config

from app.config import (
    AWS_API_TIMEOUT_SECONDS,
    AWS_REGION,
    LOAD_BALANCER_ARN,
    TARGET_GROUP_ARN,
)
from app.models import Incident, TargetHealthEvidence


class ALBDiagnosticsCollector:
    def __init__(
        self,
        client: Any | None = None,
        region_name: str | None = None,
    ) -> None:
        self.client = client or boto3.client(
            "elbv2",
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
    def _extract_target_group_name(value: str) -> str:
        normalized = value.strip()

        if ":targetgroup/" in normalized:
            normalized = normalized.split(":targetgroup/", 1)[1]

        if normalized.startswith("targetgroup/"):
            parts = normalized.split("/")
            if len(parts) >= 2:
                return parts[1]

        return normalized

    def _resolve_target_group_arn(
        self,
        incident: Incident,
    ) -> str:
        configured_arn = TARGET_GROUP_ARN

        if configured_arn:
            return configured_arn

        dimension_value = (
            incident.dimensions.get("TargetGroup")
            or incident.resource_id
        )

        if not dimension_value:
            return ""

        if dimension_value.startswith("arn:") and ":targetgroup/" in dimension_value:
            return dimension_value

        target_group_name = self._extract_target_group_name(
            dimension_value
        )

        if not target_group_name:
            return ""

        response = self.client.describe_target_groups(
            Names=[target_group_name]
        )

        target_groups = response.get("TargetGroups", [])

        if not target_groups:
            return ""

        return str(target_groups[0].get("TargetGroupArn") or "")

    @staticmethod
    def _serialize_target(
        target: dict[str, Any],
    ) -> dict[str, Any]:
        target_data = target.get("Target") or {}
        health_data = target.get("TargetHealth") or {}

        normalized_target = {}

        for key in ("Id", "Port", "AvailabilityZone"):
            value = target_data.get(key)

            if value is not None:
                normalized_target[key] = value

        normalized_health = {}

        for key in (
            "State",
            "Reason",
            "Description",
        ):
            value = health_data.get(key)

            if value is not None:
                normalized_health[key] = str(value)

        result = {
            "Target": normalized_target,
            "TargetHealth": normalized_health,
        }

        if target.get("HealthCheckPort") is not None:
            result["HealthCheckPort"] = str(
                target["HealthCheckPort"]
            )

        return result

    def collect(
        self,
        incident: Incident,
    ) -> list[TargetHealthEvidence]:
        target_group_arn = self._resolve_target_group_arn(
            incident
        )

        if not target_group_arn:
            return []

        response = self.client.describe_target_health(
            TargetGroupArn=target_group_arn
        )

        targets = [
            self._serialize_target(target)
            for target in response.get("TargetHealthDescriptions", [])
        ]

        target_group_response = self.client.describe_target_groups(
            TargetGroupArns=[target_group_arn]
        )

        target_groups = target_group_response.get(
            "TargetGroups",
            [],
        )

        load_balancer_arns = (
            target_groups[0].get("LoadBalancerArns", [])
            if target_groups
            else []
        )

        load_balancer_arn = (
            LOAD_BALANCER_ARN
            or (load_balancer_arns[0] if load_balancer_arns else "")
        )

        return [
            TargetHealthEvidence(
                target_group_arn=target_group_arn,
                targets=targets,
                load_balancer_arn=load_balancer_arn,
            )
        ]


def collect_target_health(
    incident: Incident,
    client: Any | None = None,
) -> list[TargetHealthEvidence]:
    collector = ALBDiagnosticsCollector(client=client)
    return collector.collect(incident)