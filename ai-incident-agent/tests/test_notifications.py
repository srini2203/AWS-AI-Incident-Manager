import logging
import unittest

from app.models import Incident, IncidentAnalysis
from app.workflow.audit import AuditLogger
from app.workflow.notifications import SNSNotificationService


class FakeSNS:
    def __init__(self):
        self.calls = []

    def publish(self, **kwargs):
        self.calls.append(kwargs)
        return {"MessageId": "sns-message-123"}


class NotificationTests(unittest.TestCase):
    def test_publishes_sanitized_incident_report(self):
        logger = logging.getLogger("notification-test")
        logger.handlers = [logging.NullHandler()]
        logger.propagate = False
        client = FakeSNS()
        service = SNSNotificationService(
            client=client,
            topic_arn="arn:aws:sns:ap-south-1:123456789012:incidents",
            audit_logger=AuditLogger(logger=logger),
        )
        incident = Incident("high-cpu", "HIGH", "i-123", "CPU alarm")
        analysis = IncidentAnalysis(
            summary="High CPU observed",
            probable_root_cause="CPU saturation",
            confidence=0.9,
            impact="Latency may increase",
            recommendations=["Inspect process usage"],
        )
        result = service.send_incident_report(incident, analysis, "investigation-1")
        self.assertEqual(result["status"], "SENT")
        self.assertEqual(result["message_id"], "sns-message-123")
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(client.calls[0]["TopicArn"], service.topic_arn)


if __name__ == "__main__":
    unittest.main()
