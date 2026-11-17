
from typing import Any


def get_cloudwatch_metrics(resource_id: str) -> dict[str, Any]:
    """
    Retrieve CPU and network metrics for an AWS resource.
    Currently returns simulated data.
    """
    return {
        "resource_id": resource_id,
        "cpu_utilization": 94.5,
        "network_in": 120000,
        "network_out": 85000,
        "period": "Last 15 minutes",
    }


def get_application_logs(resource_id: str) -> list[str]:
    """
    Retrieve recent application logs.
    Currently returns simulated data.
    """
    return [
        f"INFO: Application started on {resource_id}",
        "WARNING: Request processing latency increased",
        "ERROR: Database connection timeout",
        "ERROR: Failed to process incoming request",
    ]


def get_target_health() -> dict[str, Any]:
    """
    Retrieve Application Load Balancer target health.
    Currently returns simulated data.
    """
    return {
        "healthy_targets": 1,
        "unhealthy_targets": 1,
        "target_status": {
            "target-1": "healthy",
            "target-2": "unhealthy",
        },
    }
