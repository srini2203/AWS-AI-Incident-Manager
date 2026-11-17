
from app.models import Incident
from app.agent import investigate_incident
import json


def main():

    event = {
        "alarm_name": "HighCPUUtilization",
        "severity": "CRITICAL",
        "resource_id": "i-0123456789abcdef0",
        "description": "EC2 CPU utilization exceeded 90%",
    }


    incident = Incident.from_event(event)


    result = investigate_incident(incident)

    
    print("\n===== INCIDENT INVESTIGATION RESULT =====")
    print(json.dumps(result, indent=4))


if __name__ == "__main__":
    main()
