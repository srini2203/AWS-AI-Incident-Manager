import unittest

from app.analysis.analyzer import IncidentAnalyzer
from app.diagnostics.mock import MockIncidentEvidenceCollector
from app.models import Incident


class MockModeTests(unittest.TestCase):
    def test_mock_collector_and_analyzer_do_not_need_aws(self):
        incident = Incident("high-cpu", "HIGH", "i-123", "CPU alarm")
        evidence = MockIncidentEvidenceCollector().collect(incident)
        analysis = IncidentAnalyzer(mode="mock").analyze(incident, evidence)
        self.assertEqual(analysis.model_id, "local-mock")
        self.assertTrue(analysis.requires_human_approval)
        self.assertEqual(evidence.resource_metadata["diagnostics"]["mode"], "mock")
        self.assertIn("Mock", analysis.summary)


if __name__ == "__main__":
    unittest.main()
