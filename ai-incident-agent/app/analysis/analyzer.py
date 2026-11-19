from __future__ import annotations

from typing import Any

from app.analysis.bedrock import (
    BedrockInferenceClient,
    BedrockInferenceResult,
)
from app.models import Incident, IncidentAnalysis


class IncidentAnalyzer:
    def __init__(
        self,
        inference_client: BedrockInferenceClient | None = None,
    ) -> None:
        self.inference_client = (
            inference_client or BedrockInferenceClient()
        )

    @staticmethod
    def _normalize_recommendations(
        recommendations: list[str],
    ) -> list[str]:
        normalized = []
        seen = set()

        for recommendation in recommendations:
            value = recommendation.strip()

            if not value:
                continue

            key = value.casefold()

            if key not in seen:
                seen.add(key)
                normalized.append(value)

        return normalized

    @staticmethod
    def _normalize_references(
        references: list[str],
        limitations: list[str],
        security_findings: list[str],
    ) -> list[str]:
        normalized = []
        seen = set()

        entries = [
            *references,
            *[
                f"Investigation limitation: {item}"
                for item in limitations
            ],
            *[
                f"Security finding: {item}"
                for item in security_findings
            ],
        ]

        for entry in entries:
            value = entry.strip()

            if not value:
                continue

            key = value.casefold()

            if key not in seen:
                seen.add(key)
                normalized.append(value)

        return normalized

    @staticmethod
    def _validate_result(
        result: BedrockInferenceResult,
    ) -> dict[str, Any]:
        if not isinstance(result, BedrockInferenceResult):
            raise TypeError(
                "Inference client must return BedrockInferenceResult"
            )

        if not isinstance(result.analysis, dict):
            raise ValueError(
                "Bedrock inference result must contain structured analysis"
            )

        return result.analysis

    def analyze(
        self,
        incident: Incident,
        evidence: Any,
    ) -> IncidentAnalysis:
        if not isinstance(incident, Incident):
            raise TypeError(
                "incident must be an Incident instance"
            )

        inference_result = self.inference_client.analyze(
            incident=incident,
            evidence=evidence,
        )

        analysis = self._validate_result(inference_result)

        recommendations = self._normalize_recommendations(
            analysis.get("recommendations", [])
        )

        references = self._normalize_references(
            references=analysis.get("evidence_references", []),
            limitations=analysis.get("limitations", []),
            security_findings=analysis.get("security_findings", []),
        )

        return IncidentAnalysis(
            summary=analysis["summary"],
            probable_root_cause=analysis["probable_root_cause"],
            confidence=float(analysis["confidence"]),
            impact=analysis["impact"],
            recommendations=recommendations,
            evidence_references=references,
            requires_human_approval=True,
            model_id=inference_result.model_id,
            guardrail_action=inference_result.guardrail_action,
            severity=analysis["severity"],
        )


def analyze_incident(
    incident: Incident,
    evidence: Any,
    inference_client: BedrockInferenceClient | None = None,
) -> IncidentAnalysis:
    analyzer = IncidentAnalyzer(
        inference_client=inference_client,
    )

    return analyzer.analyze(
        incident=incident,
        evidence=evidence,
    )