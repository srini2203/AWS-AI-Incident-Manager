import unittest

from app.analysis.analyzer import IncidentAnalyzer
from app.analysis.bedrock import BedrockInferenceResult
from app.models import Incident


class FakeInferenceClient:
    def analyze(self, incident, evidence):
        return BedrockInferenceResult(
            analysis={
                "summary": "High CPU observed on the affected instance.",
                "probable_root_cause": "Sustained CPU utilization.",
                "confidence": 0.91,
                "impact": "Increased response latency is possible.",
                "severity": "HIGH",
                "recommendations": ["Inspect CPU-intensive processes."],
                "evidence_references": ["AWS/EC2 CPUUtilization"],
                "requires_human_approval": False,
                "limitations": [],
                "security_findings": [],
            },
            model_id="apac.amazon.nova-micro-v1:0",
            stop_reason="end_turn",
            usage={"input_tokens": 100, "output_tokens": 80, "total_tokens": 180},
            latency_ms=250,
            guardrail_action="NONE",
            guardrail_trace={},
        )


class AnalyzerTests(unittest.TestCase):
    def test_converts_bedrock_result_to_incident_analysis(self):
        incident = Incident("high-cpu", "HIGH", "i-123", "CPU alarm")
        analyzer = IncidentAnalyzer(inference_client=FakeInferenceClient())
        result = analyzer.analyze(incident, {"metrics": []})
        self.assertEqual(result.severity, "HIGH")
        self.assertTrue(result.requires_human_approval)
        self.assertEqual(result.model_id, "apac.amazon.nova-micro-v1:0")
        self.assertEqual(len(result.recommendations), 1)


if __name__ == "__main__":
    unittest.main()
