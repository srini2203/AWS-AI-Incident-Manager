from __future__ import annotations

import json
import re
from typing import Any

from strands import Agent
from strands.models import BedrockModel

from app.agent.prompts import SYSTEM_PROMPT
from app.agent.tools import build_incident_tools
from app.config import (
    AWS_REGION,
    BEDROCK_GUARDRAIL_ID,
    BEDROCK_GUARDRAIL_VERSION,
    BEDROCK_MODEL_ID,
    BEDROCK_TEMPERATURE,
    BEDROCK_TOP_P,
    BEDROCK_MAX_TOKENS,
)
from app.models import Incident, IncidentAnalysis, IncidentEvidence
from app.security.redaction import redact_payload


def _result_text(result: Any) -> str:
    if isinstance(result, str):
        return result
    message = getattr(result, "message", None)
    if isinstance(message, dict):
        blocks = message.get("content", [])
        text_blocks = [block.get("text", "") for block in blocks if isinstance(block, dict)]
        if text_blocks:
            return "\n".join(text_blocks)
    if isinstance(message, str):
        return message
    output = getattr(result, "output", None)
    if isinstance(output, str):
        return output
    return str(result)


def _parse_analysis(raw: str) -> dict[str, Any]:
    candidate = raw.strip()
    candidate = re.sub(r"^\x60{3}(?:json)?\s*|\s*\x60{3}$", "", candidate, flags=re.IGNORECASE)
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", candidate, flags=re.DOTALL)
        if not match:
            raise ValueError("Strands agent did not return a JSON incident report")
        parsed = json.loads(match.group(0))
    if not isinstance(parsed, dict):
        raise ValueError("Strands agent report must be a JSON object")
    required = ("summary", "probable_root_cause", "confidence", "impact")
    missing = [key for key in required if key not in parsed]
    if missing:
        raise ValueError(f"Strands agent report is missing required fields: {', '.join(missing)}")
    return parsed


def run_incident_agent(incident: Incident, evidence: IncidentEvidence) -> IncidentAnalysis:
    model_options: dict[str, Any] = {
        "model_id": BEDROCK_MODEL_ID,
        "region_name": AWS_REGION,
        "temperature": BEDROCK_TEMPERATURE,
        "top_p": BEDROCK_TOP_P,
        "max_tokens": BEDROCK_MAX_TOKENS,
    }
    if BEDROCK_GUARDRAIL_ID and BEDROCK_GUARDRAIL_VERSION:
        model_options.update({
            "guardrail_id": BEDROCK_GUARDRAIL_ID,
            "guardrail_version": BEDROCK_GUARDRAIL_VERSION,
            "guardrail_trace": "enabled",
            "guardrail_redact_input": True,
        })

    agent = Agent(
        model=BedrockModel(**model_options),
        tools=build_incident_tools(incident, evidence),
        system_prompt=SYSTEM_PROMPT,
    )
    safe_incident = redact_payload(incident.to_dict())
    safe_evidence_summary = redact_payload({
        "collection_errors": evidence.collection_errors,
        "resource_metadata": evidence.resource_metadata,
        "metrics_count": len(evidence.metrics),
        "log_groups_count": len(evidence.logs),
        "target_health_groups_count": len(evidence.target_health),
    })
    response = agent(
        "Investigate this AWS incident using the available evidence tools. "
        "Select only the evidence and runbook tools that are relevant. "
        "Do not assume evidence that a tool did not return. "
        "Return only the required JSON report.\n"
        f"Incident: {json.dumps(safe_incident, default=str)}\n"
        f"Evidence inventory: {json.dumps(safe_evidence_summary, default=str)}"
    )
    report = _parse_analysis(_result_text(response))
    recommendations = report.get("recommendations", [])
    references = report.get("evidence_references", [])
    limitations = report.get("limitations", [])
    if not isinstance(recommendations, list) or not isinstance(references, list) or not isinstance(limitations, list):
        raise ValueError("Strands report recommendations, evidence_references and limitations must be arrays")
    references = [str(item) for item in references]
    references.extend(f"Investigation limitation: {item}" for item in limitations)
    return IncidentAnalysis(
        summary=str(report["summary"]),
        probable_root_cause=str(report["probable_root_cause"]),
        confidence=float(report["confidence"]),
        impact=str(report["impact"]),
        recommendations=[str(item) for item in recommendations],
        evidence_references=references,
        requires_human_approval=True,
        model_id=BEDROCK_MODEL_ID,
        guardrail_action="APPLIED" if BEDROCK_GUARDRAIL_ID and BEDROCK_GUARDRAIL_VERSION else "NOT_CONFIGURED",
        severity=str(report.get("severity") or incident.severity),
    )
