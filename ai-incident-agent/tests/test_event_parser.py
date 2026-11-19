import json
import unittest

from app.event_parser import parse_event, parse_events


class EventParserTests(unittest.TestCase):
    def setUp(self):
        self.event = {
            "id": "event-123",
            "source": "aws.cloudwatch",
            "detail-type": "CloudWatch Alarm State Change",
            "account": "123456789012",
            "region": "ap-south-1",
            "time": "2026-11-19T10:00:00Z",
            "resources": ["arn:aws:cloudwatch:ap-south-1:123456789012:alarm:high-cpu"],
            "detail": {
                "alarmName": "high-cpu",
                "state": {"value": "ALARM", "reason": "CPU exceeded threshold"},
                "configuration": {"description": "High CPU alarm"},
                "trigger": {
                    "metricName": "CPUUtilization",
                    "namespace": "AWS/EC2",
                    "dimensions": [{"name": "InstanceId", "value": "i-0123456789abcdef0"}],
                },
            },
        }

    def test_parse_eventbridge_alarm(self):
        incident = parse_event(self.event)
        self.assertEqual(incident.alarm_name, "high-cpu")
        self.assertEqual(incident.resource_id, "i-0123456789abcdef0")
        self.assertEqual(incident.severity, "HIGH")
        self.assertEqual(incident.metric_name, "CPUUtilization")
        self.assertEqual(incident.account_id, "123456789012")

    def test_parse_sns_cloudwatch_notification(self):
        message = {
            "AlarmName": "high-cpu",
            "NewStateValue": "ALARM",
            "NewStateReason": "CPU exceeded threshold",
            "StateChangeTime": "2026-11-19T10:00:00Z",
            "Trigger": {
                "MetricName": "CPUUtilization",
                "Namespace": "AWS/EC2",
                "Dimensions": [{"name": "InstanceId", "value": "i-0123456789abcdef0"}],
            },
        }
        sns_event = {"Records": [{"EventSource": "aws:sns", "Sns": {"Message": json.dumps(message)}}]}
        incident = parse_event(sns_event)
        self.assertEqual(incident.alarm_name, "high-cpu")
        self.assertEqual(incident.source, "sns-cloudwatch")

    def test_parse_event_batch(self):
        incidents = parse_events([self.event, self.event])
        self.assertEqual(len(incidents), 2)

    def test_reject_invalid_json(self):
        with self.assertRaises(ValueError):
            parse_event("{bad-json")


if __name__ == "__main__":
    unittest.main()
