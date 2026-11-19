import unittest

from app.security.evidence import prepare_evidence_for_analysis
from app.security.redaction import redact_payload, redact_text


class SecurityTests(unittest.TestCase):
    def test_redacts_password_and_access_key(self):
        text = "password=hunter2 aws_access_key_id=AKIA1234567890ABCDEF"
        sanitized = redact_text(text)
        self.assertNotIn("hunter2", sanitized)
        self.assertNotIn("AKIA1234567890ABCDEF", sanitized)

    def test_redacts_sensitive_mapping_fields(self):
        sanitized = redact_payload({"username": "ops", "client_secret": "secret-value"})
        self.assertEqual(sanitized["client_secret"], "[REDACTED]")
        self.assertEqual(sanitized["username"], "ops")

    def test_prepares_bedrock_evidence(self):
        evidence = {
            "metrics": [],
            "logs": [{"log_group": "/app", "entries": [{"@message": "password=private"}]}],
            "target_health": [],
            "collected_at": "2026-11-19T10:00:00+00:00",
            "collection_errors": [],
            "resource_metadata": {"resource_id": "i-123"},
        }
        prepared = prepare_evidence_for_analysis(evidence)
        self.assertEqual(prepared["logs"][0]["entries"][0]["@message"], "password=[REDACTED]")
        self.assertIn("trust_boundary", prepared)

    def test_rejects_unknown_top_level_fields(self):
        with self.assertRaises(ValueError):
            prepare_evidence_for_analysis({"metrics": [], "unexpected": True})


if __name__ == "__main__":
    unittest.main()
