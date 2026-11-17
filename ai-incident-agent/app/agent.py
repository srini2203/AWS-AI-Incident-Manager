
from app.models import Incident
from app.tools import (
    get_cloudwatch_metrics,
    get_application_logs,
    get_target_health,
)
from app.analyzer import analyze_incident


def investigate_incident(incident: Incident) -> dict:
    """
    Collect diagnostic evidence and generate an incident analysis.
    """

    print(f"Investigating: {incident.alarm_name}")

    # Step 1: Collect diagnostic evidence
    metrics = get_cloudwatch_metrics(incident.resource_id)
    logs = get_application_logs(incident.resource_id)
    target_health = get_target_health()

    investigation = {
        "incident": {
            "alarm_name": incident.alarm_name,
            "severity": incident.severity,
            "resource_id": incident.resource_id,
            "description": incident.description,
            "timestamp": incident.timestamp,
        },
        "evidence": {
            "metrics": metrics,
            "logs": logs,
            "target_health": target_health,
        },
    }

    # Step 2: Analyze collected evidence
    analysis = analyze_incident(investigation)

    # Step 3: Return complete investigation report
    return {
        "investigation": investigation,
        "analysis": analysis,
    }
