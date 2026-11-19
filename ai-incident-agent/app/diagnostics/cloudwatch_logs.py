from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from botocore.config import Config

from app.config import (
    AWS_API_TIMEOUT_SECONDS,
    AWS_REGION,
    CLOUDWATCH_LOG_GROUPS,
    CLOUDWATCH_LOG_LOOKBACK_MINUTES,
    CLOUDWATCH_LOG_QUERY_TIMEOUT_SECONDS,
    MAX_LOG_ENTRIES,
    MAX_LOG_ENTRY_LENGTH,
)
from app.models import Incident, LogEvidence


class CloudWatchLogsCollector:
    def __init__(
        self,
        client: Any | None = None,
        region_name: str | None = None,
    ) -> None:
        self.client = client or boto3.client(
            "logs",
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
    def _query_string() -> str:
        return (
            "fields @timestamp, @message, @logStream, @log "
            "| sort @timestamp desc "
            f"| limit {MAX_LOG_ENTRIES}"
        )

    @staticmethod
    def _normalize_result(
        result: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []

        for row in result:
            entry: dict[str, Any] = {}

            for field in row:
                name = str(field.get("field", ""))
                value = field.get("value", "")

                if not name:
                    continue

                if name == "@message":
                    value = str(value)[:MAX_LOG_ENTRY_LENGTH]
                else:
                    value = str(value)

                entry[name] = value

            entries.append(entry)

        return entries

    def _execute_query(
        self,
        log_groups: list[str],
        start_time: datetime,
        end_time: datetime,
    ) -> list[dict[str, Any]]:
        response = self.client.start_query(
            logGroupNames=log_groups,
            startTime=int(start_time.timestamp()),
            endTime=int(end_time.timestamp()),
            queryString=self._query_string(),
            limit=MAX_LOG_ENTRIES,
        )

        query_id = response["queryId"]
        deadline = (
            time.monotonic()
            + CLOUDWATCH_LOG_QUERY_TIMEOUT_SECONDS
        )

        while time.monotonic() < deadline:
            query_response = self.client.get_query_results(
                queryId=query_id
            )

            status = query_response.get("status", "")

            if status == "Complete":
                return self._normalize_result(
                    query_response.get("results", [])
                )

            if status in {
                "Failed",
                "Cancelled",
                "Timeout",
            }:
                raise RuntimeError(
                    f"CloudWatch Logs Insights query {status.lower()}"
                )

            time.sleep(0.5)

        try:
            self.client.stop_query(queryId=query_id)
        except Exception:
            pass

        raise TimeoutError(
            "CloudWatch Logs Insights query exceeded its execution timeout"
        )

    @staticmethod
    def _time_window(
        incident: Incident,
    ) -> tuple[datetime, datetime]:
        incident_time = CloudWatchLogsCollector._parse_timestamp(
            incident.timestamp
        )

        start_time = incident_time - timedelta(
            minutes=CLOUDWATCH_LOG_LOOKBACK_MINUTES
        )

        current_time = datetime.now(timezone.utc)

        end_time = min(
            incident_time + timedelta(minutes=5),
            current_time,
        )

        if end_time <= start_time:
            end_time = min(
                start_time + timedelta(minutes=1),
                current_time,
            )

        return start_time, end_time

    @staticmethod
    def _group_batches(groups: list[str]) -> list[list[str]]:
        return [
            groups[index:index + 50]
            for index in range(0, len(groups), 50)
        ]

    def collect(
        self,
        incident: Incident,
        log_groups: list[str] | None = None,
    ) -> list[LogEvidence]:
        configured_groups = (
            log_groups
            if log_groups is not None
            else CLOUDWATCH_LOG_GROUPS
        )

        groups = list(
            dict.fromkeys(
                group.strip()
                for group in configured_groups
                if group and group.strip()
            )
        )

        if not groups:
            return []

        start_time, end_time = self._time_window(incident)
        query = self._query_string()

        evidence: list[LogEvidence] = []
        errors: list[str] = []

        for batch in self._group_batches(groups):
            try:
                entries = self._execute_query(
                    log_groups=batch,
                    start_time=start_time,
                    end_time=end_time,
                )

                evidence.append(
                    LogEvidence(
                        log_group=",".join(batch),
                        entries=entries,
                        query=query,
                        start_time=start_time.isoformat(),
                        end_time=end_time.isoformat(),
                        truncated=len(entries) >= MAX_LOG_ENTRIES,
                    )
                )

            except Exception as exc:
                errors.append(
                    f"{','.join(batch)}: {type(exc).__name__}"
                )

        if errors and not evidence:
            raise RuntimeError(
                "CloudWatch log collection failed: "
                + "; ".join(errors)
            )

        return evidence


def collect_logs(
    incident: Incident,
    client: Any | None = None,
    log_groups: list[str] | None = None,
) -> list[LogEvidence]:
    collector = CloudWatchLogsCollector(client=client)

    return collector.collect(
        incident=incident,
        log_groups=log_groups,
    )