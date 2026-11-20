from __future__ import annotations

import unittest

from app.agent.incident_agent import _parse_analysis, _result_text


class StrandsAgentOutputTests(unittest.TestCase):
    def test_parse_plain_json_report(self) -> None:
        report = {
            "summary": "ALB target health degraded",
            "probable_root_cause": "Targets are failing health checks",
            "confidence": 0.82,
            "impact": "Some requests may fail",
            "recommendations": ["Review target health"],
            "evidence_references": ["target-health tool"],
            "limitations": [],
            "severity": "HIGH",
        }
        parsed = _parse_analysis(__import__("json").dumps(report))
        self.assertEqual(parsed["probable_root_cause"], report["probable_root_cause"])
        self.assertEqual(parsed["confidence"], 0.82)

    def test_parse_markdown_fenced_json(self) -> None:
        raw = """\x60\x60\x60json
{"summary":"s","probable_root_cause":"r","confidence":0.5,"impact":"i"}
\x60\x60\x60"""
        parsed = _parse_analysis(raw)
        self.assertEqual(parsed["summary"], "s")

    def test_reject_non_json_report(self) -> None:
        with self.assertRaises(ValueError):
            _parse_analysis("No structured report was returned")

    def test_reject_missing_required_fields(self) -> None:
        with self.assertRaises(ValueError):
            _parse_analysis('{"summary":"only"}')

    def test_extract_text_from_agent_message(self) -> None:
        class Result:
            message = {"content": [{"text": '{"summary":"ok"}'}]}

        self.assertEqual(_result_text(Result()), '{"summary":"ok"}')


if __name__ == "__main__":
    unittest.main()
