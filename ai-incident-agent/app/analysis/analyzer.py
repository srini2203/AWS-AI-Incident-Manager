from __future__ import annotations

from typing import Any

from app.analysis.bedrock import (
    BedrockInferenceClient,
    BedrockInferenceResult,
)
from app.config import ANALYZER_MODE
from app.models import Incident, IncidentAnalysis


class IncidentAnalyzer:
    def __init__(
        self,
        inference_client: BedrockInferenceClient | None = None,
        mode: str | None = None,
    ) -> None:
        self.mode = (mode or ANALYZER_MODE).strip().lower()
        if self.mode not in {"mock", "bedrock"}:
            raise ValueError("Analyzer mode must be mock or bedrock")
        self.use_mock = self.mode == "mock" and inference_client is None
        self.inference_client = inference_client
        if not self.use_mock and self.inference_client is None:
            self.inference_client = BedrockInferenceClient()

    @staticmethod
    def _normalize_recommendations(
        recommendations: list[str],
    ) -> list[str]:
        normalized = []
        seen = set()
        for recommendation in recommendations:
            value = str(recommendation).strip()
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
            *[f"Investigation limitation: {item}" for item in limitations],
            *[f"Security finding: {item}" for item in security_findings],
        ]
        for entry in entries:
            value = str(entry).strip()
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
            raise TypeError("Inference client must return BedrockInferenceResult")
        if not isinstance(result.analysis, dict):
            raise ValueError("Bedrock inference result must contain structured analysis")
        return result.analysis

    @staticmethod
    def _mock_analysis(
        incident: Incident,
        evidence: Any,
    ) -> IncidentAnalysis:
        target_health = getattr(evidence, "target_health", [])
        unhealthy_targets = sum(
            1
            for group in target_health
            for target in group.targets
            if str(target.get("TargetHealth", {}).get("State", "")).lower()
            in {"unhealthy", "unused", "draining"}
        )
        metrics = getattr(evidence, "metrics", [])
        high_metrics = [
            item
            for item in metrics
            if any(
                float(point.get("average", point.get("Average", 0)) or 0) >= 80
                for point in item.datapoints
            )
        ]
        if unhealthy_targets:
            probable_root_cause = "One or more application load-balancer targets are unhealthy."
            confidence = 0.82
        elif high_metrics:
            probable_root_cause = "Elevated infrastructure metric values may be contributing to the alarm."
            confidence = 0.76
        else:
            probable_root_cause = "The mock evidence does not establish a definitive root cause."
            confidence = 0.45
        recommendations = [
            "Review the affected instance and application logs.",
            "Check target health and recent deployment or configuration changes.",
            "Compare metric trends with the incident start time.",
        ]
        references = [
            "Mock diagnostic evidence only; no AWS APIs were queried.",
            f"Alarm: {incident.alarm_name}",
            f"Resource: {incident.resource_id}",
        ]
        return IncidentAnalysis(
            summary="Local mock analysis completed. This report is illustrative and is not an AWS incident diagnosis.",
            probable_root_cause=probable_root_cause,
            confidence=confidence,
            impact="Potential application availability or response-time degradation; confirm using live telemetry.",
            recommendations=recommendations,
            evidence_references=references,
            requires_human_approval=True,
            model_id="local-mock",
            severity=incident.severity,
        )

    def analyze(
        self,
        incident: Incident,
        evidence: Any,
    ) -> IncidentAnalysis:
        if not isinstance(incident, Incident):
            raise TypeError("incident must be an Incident instance")
        if self.use_mock:
            return self._mock_analysis(incident, evidence)
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
    analyzer = IncidentAnalyzer(inference_client=inference_client)
    return analyzer.analyze(incident=incident, evidence=evidence)
