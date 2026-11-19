from __future__ import annotations

import json
import random
import re
import time
from dataclasses import dataclass
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from app.analysis.prompts import (
    build_converse_messages,
    build_system_prompt,
)
from app.config import (
    AWS_API_TIMEOUT_SECONDS,
    AWS_REGION,
    BEDROCK_CONNECT_TIMEOUT_SECONDS,
    BEDROCK_GUARDRAIL_ID,
    BEDROCK_GUARDRAIL_VERSION,
    BEDROCK_MAX_EVIDENCE_CHARS,
    BEDROCK_MAX_TOKENS,
    BEDROCK_MODEL_ID,
    BEDROCK_READ_TIMEOUT_SECONDS,
    BEDROCK_RETRY_ATTEMPTS,
    BEDROCK_TEMPERATURE,
    BEDROCK_TOP_P,
    ENABLE_BEDROCK_GUARDRAILS,
)
from app.models import Incident
from app.security.evidence import prepare_evidence_for_analysis


RETRYABLE_ERROR_CODES = {
    "ThrottlingException",
    "TooManyRequestsException",
    "ServiceUnavailableException",
    "InternalServerException",
    "ModelNotReadyException",
    "ModelTimeoutException",
    "RequestTimeout",
    "RequestTimeoutException",
    "PriorRequestNotComplete",
}

REQUIRED_RESPONSE_FIELDS = {
    "summary",
    "probable_root_cause",
    "confidence",
    "impact",
    "severity",
    "recommendations",
    "evidence_references",
    "requires_human_approval",
    "limitations",
    "security_findings",
}


class BedrockInferenceError(RuntimeError):
    pass


class BedrockResponseError(BedrockInferenceError):
    pass


class BedrockGuardrailError(BedrockInferenceError):
    pass


@dataclass(slots=True)
class BedrockInferenceResult:
    analysis: dict[str, Any]
    model_id: str
    stop_reason: str
    usage: dict[str, int]
    latency_ms: int
    guardrail_action: str
    guardrail_trace: dict[str, Any]


class BedrockInferenceClient:
    def __init__(
        self,
        client: Any | None = None,
        region_name: str | None = None,
        model_id: str | None = None,
    ) -> None:
        self.model_id = model_id or BEDROCK_MODEL_ID

        self.client = client or boto3.client(
            "bedrock-runtime",
            region_name=region_name or AWS_REGION,
            config=Config(
                connect_timeout=BEDROCK_CONNECT_TIMEOUT_SECONDS,
                read_timeout=BEDROCK_READ_TIMEOUT_SECONDS,
                retries={
                    "max_attempts": 1,
                    "mode": "standard",
                },
                user_agent_extra="aws-ai-incident-triage-agent",
            ),
        )

    @staticmethod
    def _extract_text(response: dict[str, Any]) -> str:
        output = response.get("output") or {}
        message = output.get("message") or {}
        content_blocks = message.get("content") or []

        text_blocks = [
            block["text"]
            for block in content_blocks
            if isinstance(block, dict)
            and isinstance(block.get("text"), str)
        ]

        if not text_blocks:
            raise BedrockResponseError(
                "Bedrock returned no textual analysis"
            )

        return "\n".join(text_blocks).strip()

    @staticmethod
    def _extract_json(text: str) -> dict[str, Any]:
        normalized = text.strip()

        normalized = re.sub(
            r"^```(?:json)?\s*",
            "",
            normalized,
            flags=re.IGNORECASE,
        )

        normalized = re.sub(
            r"\s*```$",
            "",
            normalized,
        )

        try:
            parsed = json.loads(normalized)
        except json.JSONDecodeError:
            decoder = json.JSONDecoder()
            start = normalized.find("{")

            if start < 0:
                raise BedrockResponseError(
                    "Bedrock response does not contain a JSON object"
                )

            try:
                parsed, _ = decoder.raw_decode(
                    normalized[start:]
                )
            except json.JSONDecodeError as exc:
                raise BedrockResponseError(
                    "Bedrock returned malformed JSON"
                ) from exc

        if not isinstance(parsed, dict):
            raise BedrockResponseError(
                "Bedrock analysis must be a JSON object"
            )

        return parsed

    @staticmethod
    def _validate_analysis(
        analysis: dict[str, Any],
    ) -> dict[str, Any]:
        missing = REQUIRED_RESPONSE_FIELDS - set(analysis)

        if missing:
            raise BedrockResponseError(
                "Bedrock response is missing required fields: "
                + ", ".join(sorted(missing))
            )

        for field in (
            "summary",
            "probable_root_cause",
            "impact",
            "severity",
        ):
            if not isinstance(analysis[field], str):
                raise BedrockResponseError(
                    f"Bedrock response field {field} must be a string"
                )

        if not isinstance(analysis["confidence"], (int, float)):
            raise BedrockResponseError(
                "Bedrock confidence must be numeric"
            )

        confidence = float(analysis["confidence"])

        if not 0.0 <= confidence <= 1.0:
            raise BedrockResponseError(
                "Bedrock confidence must be between 0 and 1"
            )

        for field in (
            "recommendations",
            "evidence_references",
            "limitations",
            "security_findings",
        ):
            if not isinstance(analysis[field], list):
                raise BedrockResponseError(
                    f"Bedrock response field {field} must be a list"
                )

            if not all(
                isinstance(item, str)
                for item in analysis[field]
            ):
                raise BedrockResponseError(
                    f"Bedrock response field {field} must contain strings"
                )

        if not isinstance(
            analysis["requires_human_approval"],
            bool,
        ):
            raise BedrockResponseError(
                "requires_human_approval must be boolean"
            )

        valid_severities = {
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO",
        }

        severity = analysis["severity"].upper()

        if severity not in valid_severities:
            raise BedrockResponseError(
                "Bedrock returned an unsupported severity"
            )

        validated = dict(analysis)
        validated["severity"] = severity
        validated["confidence"] = confidence
        validated["requires_human_approval"] = True

        return validated

    @staticmethod
    def _guardrail_metadata(
        response: dict[str, Any],
    ) -> tuple[str, dict[str, Any]]:
        stop_reason = str(
            response.get("stopReason") or "unknown"
        )

        trace = response.get("trace") or {}
        guardrail_trace = trace.get("guardrail") or {}

        action = (
            "INTERVENED"
            if stop_reason == "guardrail_intervened"
            else "NONE"
        )

        if guardrail_trace:
            action = str(
                guardrail_trace.get("action") or action
            ).upper()

        return action, guardrail_trace

    def _build_request(
        self,
        incident: Incident,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        request: dict[str, Any] = {
            "modelId": self.model_id,
            "system": [
                {
                    "text": build_system_prompt()
                }
            ],
            "messages": build_converse_messages(
                incident=incident,
                evidence=evidence,
            ),
            "inferenceConfig": {
                "maxTokens": BEDROCK_MAX_TOKENS,
                "temperature": BEDROCK_TEMPERATURE,
                "topP": BEDROCK_TOP_P,
            },
            "requestMetadata": {
                "application": "aws-ai-incident-triage-agent",
                "incident_id": incident.event_id,
                "prompt_version": "1.0",
            },
        }

        if ENABLE_BEDROCK_GUARDRAILS:
            request["guardrailConfig"] = {
                "guardrailIdentifier": BEDROCK_GUARDRAIL_ID,
                "guardrailVersion": BEDROCK_GUARDRAIL_VERSION,
                "trace": "enabled",
            }

        return request

    def _invoke_with_retry(
        self,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        last_error: Exception | None = None

        for attempt in range(BEDROCK_RETRY_ATTEMPTS):
            try:
                return self.client.converse(**request)

            except ClientError as exc:
                last_error = exc

                error_response = exc.response.get("Error", {})
                error_code = error_response.get(
                    "Code",
                    "UnknownError",
                )

                if error_code not in RETRYABLE_ERROR_CODES:
                    raise BedrockInferenceError(
                        f"Bedrock invocation failed: {error_code}"
                    ) from exc

                if attempt == BEDROCK_RETRY_ATTEMPTS - 1:
                    break

                retry_delay = min(
                    2 ** attempt + random.uniform(0, 1),
                    20,
                )

                time.sleep(retry_delay)

            except BotoCoreError as exc:
                last_error = exc

                if attempt == BEDROCK_RETRY_ATTEMPTS - 1:
                    break

                retry_delay = min(
                    2 ** attempt + random.uniform(0, 1),
                    20,
                )

                time.sleep(retry_delay)

        raise BedrockInferenceError(
            "Bedrock invocation failed after retry attempts"
        ) from last_error

    def analyze(
        self,
        incident: Incident,
        evidence: Any,
    ) -> BedrockInferenceResult:
        if not isinstance(incident, Incident):
            raise TypeError(
                "incident must be an Incident instance"
            )

        sanitized_evidence = prepare_evidence_for_analysis(
            evidence,
            maximum_chars=BEDROCK_MAX_EVIDENCE_CHARS,
        )

        request = self._build_request(
            incident=incident,
            evidence=sanitized_evidence,
        )

        started_at = time.monotonic()

        response = self._invoke_with_retry(request)

        latency_ms = int(
            (time.monotonic() - started_at) * 1000
        )

        stop_reason = str(
            response.get("stopReason") or "unknown"
        )

        guardrail_action, guardrail_trace = (
            self._guardrail_metadata(response)
        )

        if stop_reason == "guardrail_intervened":
            raise BedrockGuardrailError(
                "Bedrock Guardrails intervened and blocked the analysis"
            )

        if stop_reason == "max_tokens":
            raise BedrockResponseError(
                "Bedrock analysis was truncated by the token limit"
            )

        if stop_reason not in {"end_turn", "stop_sequence"}:
            raise BedrockResponseError(
                f"Bedrock returned unexpected stop reason: {stop_reason}"
            )

        response_text = self._extract_text(response)

        parsed_analysis = self._extract_json(
            response_text
        )

        validated_analysis = self._validate_analysis(
            parsed_analysis
        )

        usage_data = response.get("usage") or {}

        usage = {
            "input_tokens": int(
                usage_data.get("inputTokens", 0)
            ),
            "output_tokens": int(
                usage_data.get("outputTokens", 0)
            ),
            "total_tokens": int(
                usage_data.get("totalTokens", 0)
            ),
        }

        return BedrockInferenceResult(
            analysis=validated_analysis,
            model_id=self.model_id,
            stop_reason=stop_reason,
            usage=usage,
            latency_ms=latency_ms,
            guardrail_action=guardrail_action,
            guardrail_trace=guardrail_trace,
        )


def invoke_bedrock(
    incident: Incident,
    evidence: Any,
    client: Any | None = None,
) -> BedrockInferenceResult:
    inference_client = BedrockInferenceClient(
        client=client,
    )

    return inference_client.analyze(
        incident=incident,
        evidence=evidence,
    )