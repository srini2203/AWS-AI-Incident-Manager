import unittest

from app.diagnostics.collector import IncidentEvidenceCollector
from app.models import Incident, LogEvidence, MetricEvidence, TargetHealthEvidence


class FakeMetrics:
    def collect(self, incident):
        return [MetricEvidence("AWS/EC2", "CPUUtilization", {"InstanceId": incident.resource_id}, [{"average": 91.0}])]


class FakeLogs:
    def collect(self, incident):
        return [LogEvidence("/app", [{"@message": "worker request timed out"}])]


class FakeALB:
    def collect(self, incident):
        return [TargetHealthEvidence("arn:target", [{"TargetHealth": {"State": "unhealthy"}}])]


class DiagnosticsTests(unittest.TestCase):
    def test_collects_and_combines_evidence(self):
        incident = Incident(
            alarm_name="high-cpu",
            severity="HIGH",
            resource_id="i-0123456789abcdef0",
            description="CPU exceeded threshold",
            dimensions={"TargetGroup": "targetgroup/app/123"},
        )
        collector = IncidentEvidenceCollector(
            metrics_collector=FakeMetrics(),
            logs_collector=FakeLogs(),
            alb_collector=FakeALB(),
            max_concurrency=3,
        )
        evidence = collector.collect(incident)
        self.assertEqual(len(evidence.metrics), 1)
        self.assertEqual(len(evidence.logs), 1)
        self.assertEqual(len(evidence.target_health), 1)
        self.assertEqual(evidence.resource_metadata["diagnostics"]["collectors_completed"], 3)

    def test_partial_collection_failure_is_recorded(self):
        class FailingLogs:
            def collect(self, incident):
                raise RuntimeError("unavailable")

        incident = Incident("alarm", "HIGH", "i-123", "description")
        collector = IncidentEvidenceCollector(
            metrics_collector=FakeMetrics(),
            logs_collector=FailingLogs(),
            alb_collector=FakeALB(),
            max_concurrency=3,
        )
        evidence = collector.collect(incident)
        self.assertTrue(evidence.collection_errors)
        self.assertEqual(len(evidence.metrics), 1)


if __name__ == "__main__":
    unittest.main()
