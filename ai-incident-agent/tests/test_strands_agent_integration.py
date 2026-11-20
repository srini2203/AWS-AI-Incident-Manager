from __future__ import annotations

import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from app.agent import incident_agent
from app.models import Incident, IncidentEvidence
from app.rag.knowledge_base import retrieve_runbook_context


class IncidentAgentParsingTests(unittest.TestCase):
    def test_parse_analysis_accepts_plain_json(self) -> None:
        payload = {
            "summary": "ALB targets are unhealthy",
            "probable_root_cause": "Application health check failures",
            "confidence": 0.82,
            "impact": "Requests may fail",
            "recommendations": ["Inspect application health endpoint"],
            "evidence_references": ["target-health"],
            "limitations": [],
        }
        self.assertEqual(incident_agent._parse_analysis(json.dumps(payload)), payload)

    def test_parse_analysis_accepts_markdown_json_fence(self) -> None:
        raw = ' ```json\n{"summary":"s","probable_root_cause":"r","confidence":0.5,"impact":"i"}\n``` '
        self.assertEqual(incident_agent._parse_analysis(raw)["summary"], "s")

    def test_parse_analysis_rejects_non_json(self) -> None:
        with self.assertRaisesRegex(ValueError, "did not return a JSON"):
            incident_agent._parse_analysis("not a report")

    def test_parse_analysis_rejects_missing_required_fields(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing required fields"):
            incident_agent._parse_analysis('{"summary":"incomplete"}')

    def test_result_text_extracts_strands_message_blocks(self) -> None:
        result = SimpleNamespace(
            message={"content": [{"text": "first"}, {"text": "second"}]}
        )
        self.assertEqual(incident_agent._result_text(result), "first\nsecond")


class IncidentAgentInvocationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.incident = Incident(
            alarm_name="HighCPU",
            severity="HIGH",
            resource_id="i-0123456789",
            description="CPU utilization exceeded threshold",
        )
        self.evidence = IncidentEvidence()

    @patch("app.agent.incident_agent.build_incident_tools", return_value=["tool"])
    @patch("app.agent.incident_agent.BedrockModel")
    @patch("app.agent.incident_agent.Agent")
    def test_invokes_strands_and_maps_report_to_domain_model(
        self, agent_cls: Mock, model_cls: Mock, tools_factory: Mock
    ) -> None:
        report = {
            "summary": "CPU is elevated",
            "probable_root_cause": "A batch process",
            "confidence": 0.9,
            "impact": "Elevated latency",
            "severity": "HIGH",
            "recommendations": ["Inspect the batch process"],
            "evidence_references": ["cloudwatch-metrics"],
            "limitations": ["No application trace data"],
        }
        agent_instance = Mock(return_value=SimpleNamespace(
            message={"content": [{"text": json.dumps(report)}]}
        ))
        agent_cls.return_value = agent_instance

        with patch.multiple(
            "app.agent.incident_agent",
            BEDROCK_MODEL_ID="test-model",
            BEDROCK_GUARDRAIL_ID="guardrail-id",
            BEDROCK_GUARDRAIL_VERSION="1",
        ):
            result = incident_agent.run_incident_agent(self.incident, self.evidence)

        tools_factory.assert_called_once_with(self.incident, self.evidence)
        model_cls.assert_called_once()
        model_options = model_cls.call_args.kwargs
        self.assertEqual(model_options["model_id"], "test-model")
        self.assertEqual(model_options["guardrail_id"], "guardrail-id")
        self.assertEqual(model_options["guardrail_version"], "1")
        agent_cls.assert_called_once()
        agent_instance.assert_called_once()
        self.assertEqual(result.summary, "CPU is elevated")
        self.assertEqual(result.probable_root_cause, "A batch process")
        self.assertEqual(result.confidence, 0.9)
        self.assertTrue(result.requires_human_approval)
        self.assertEqual(result.model_id, "test-model")
        self.assertEqual(result.guardrail_action, "APPLIED")
        self.assertIn(
            "Investigation limitation: No application trace data",
            result.evidence_references,
        )

    @patch("app.agent.incident_agent.build_incident_tools", return_value=[])
    @patch("app.agent.incident_agent.BedrockModel")
    @patch("app.agent.incident_agent.Agent")
    def test_rejects_invalid_agent_report(
        self, agent_cls: Mock, _model_cls: Mock, _tools_factory: Mock
    ) -> None:
        agent_cls.return_value = Mock(return_value="not-json")
        with self.assertRaisesRegex(ValueError, "did not return a JSON"):
            incident_agent.run_incident_agent(self.incident, self.evidence)


class KnowledgeBaseRetrievalTests(unittest.TestCase):
    def test_retrieves_and_redacts_runbook_passages(self) -> None:
        client = Mock()
        client.retrieve.return_value = {
            "retrievalResults": [
                {
                    "content": {"text": "Check target group health"},
                    "location": {"s3Location": {"uri": "s3://runbooks/alb.md"}},
                    "score": 0.91,
                }
            ]
        }

        results = retrieve_runbook_context(
            query="ALB targets unhealthy",
            knowledge_base_id="kb-test",
            client=client,
        )

        client.retrieve.assert_called_once()
        request = client.retrieve.call_args.kwargs
        self.assertEqual(request["knowledgeBaseId"], "kb-test")
        self.assertEqual(request["retrievalQuery"]["text"], "ALB targets unhealthy")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["content"], "Check target group health")
        self.assertEqual(results[0]["source"], "s3://runbooks/alb.md")
        self.assertEqual(results[0]["score"], 0.91)

    def test_retrieval_requires_knowledge_base_id(self) -> None:
        with patch.dict("os.environ", {"BEDROCK_KNOWLEDGE_BASE_ID": ""}):
            with self.assertRaisesRegex(ValueError, "BEDROCK_KNOWLEDGE_BASE_ID"):
                retrieve_runbook_context("ALB targets unhealthy", knowledge_base_id="")

    def test_retrieval_rejects_blank_query(self) -> None:
        with self.assertRaisesRegex(ValueError, "query cannot be empty"):
            retrieve_runbook_context("   ", knowledge_base_id="kb-test")


if __name__ == "__main__":
    unittest.main()
