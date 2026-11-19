from __future__ import annotations

from app.models import (
    Incident,
    IncidentEvidence,
    LogEvidence,
    MetricEvidence,
    TargetHealthEvidence,
)


class MockIncidentEvidenceCollector:
    def collect(self, incident: Incident) -> IncidentEvidence:
        if not isinstance(incident, Incident):
            raise TypeError("incident must be an Incident instance")

        return IncidentEvidence(
            metrics=[
                MetricEvidence(
                    namespace=incident.metric_namespace or "AWS/EC2",
                    metric_name=incident.metric_name or "CPUUtilization",
                    dimensions=incident.dimensions or {"InstanceId": incident.resource_id},
                    datapoints=[
                        {
                            "timestamp": incident.timestamp,
                            "average": 91.0,
                            "maximum": 96.0,
                            "unit": "Percent",
                        }
                    ],
                    unit="Percent",
                    period_seconds=60,
                    statistic="Average",
                )
            ],
            logs=[
                LogEvidence(
                    log_group="/mock/application",
                    entries=[
                        {
                            "timestamp": incident.timestamp,
                            "@message": "Mock diagnostic: application request latency increased",
                        }
                    ],
                    query="mock diagnostic query",
                    start_time=incident.timestamp,
                    end_time=incident.timestamp,
                )
            ],
            target_health=[
                TargetHealthEvidence(
                    target_group_arn="mock-target-group",
                    targets=[
                        {
                            "Target": {"Id": incident.resource_id},
                            "TargetHealth": {
                                "State": "unhealthy",
                                "Reason": "Target.FailedHealthChecks",
                                "Description": "Mock-only diagnostic evidence",
                            },
                        }
                    ],
                )
            ],
            resource_metadata={
                "resource_id": incident.resource_id,
                "alarm_name": incident.alarm_name,
                "region": incident.region,
                "diagnostics": {
                    "mode": "mock",
                    "collectors_requested": [
                        "mock_metrics",
                        "mock_logs",
                        "mock_target_health",
                    ],
                    "collectors_completed": 3,
                    "collectors_failed": 0,
                },
            },
        )
