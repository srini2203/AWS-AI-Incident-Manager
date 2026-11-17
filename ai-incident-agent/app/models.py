
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Incident:
    alarm_name: str
    severity: str
    resource_id: str
    description: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @classmethod
    def from_event(cls, event: dict[str, Any]) -> "Incident":
        return cls(
            alarm_name=event["alarm_name"],
            severity=event["severity"],
            resource_id=event["resource_id"],
            description=event["description"],
            timestamp=event.get(
                "timestamp",
                datetime.now(timezone.utc).isoformat()
            ),
        )
