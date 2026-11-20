from __future__ import annotations

import os
from typing import Any

from strands import Agent
from strands.models import BedrockModel

from app.agent.prompts import SYSTEM_PROMPT
from app.agent.tools import build_incident_tools
from app.config import (
    BEDROCK_GUARDRAIL_ID,
    BEDROCK_GUARDRAIL_VERSION,
    BEDROCK_MODEL_ID,
    BEDROCK_TEMPERATURE,
    BEDROCK_MAX_TOKENS,
)
from app.models import Incident


def run_incident_agent(incident: Incident) -> Any:
    model_options: dict[str, Any] = {
        "model_id": BEDROCK_MODEL_ID,
        "temperature": BEDROCK_TEMPERATURE,
        "max_tokens": BEDROCK_MAX_TOKENS,
    }

    if BEDROCK_GUARDRAIL_ID and BEDROCK_GUARDRAIL_VERSION:
        model_options["guardrail_id"] = BEDROCK_GUARDRAIL_ID
        model_options["guardrail_version"] = BEDROCK_GUARDRAIL_VERSION
        model_options["guardrail_trace"] = "enabled"

    model = BedrockModel(**model_options)
    agent = Agent(
        model=model,
        tools=build_incident_tools(incident),
        system_prompt=SYSTEM_PROMPT,
    )

    prompt = (
        "Investigate this AWS incident. Use the available tools selectively, "
        "follow evidence, and return the required JSON report.\n"
        f"Incident: {incident.to_dict()}"
    )
    return agent(prompt)
