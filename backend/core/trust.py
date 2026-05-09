"""
Finding trust/explainability enrichment.

Adds human-facing trust messages:
- why_flagged
- why_not_ignored

This layer runs centrally after rule execution.
"""

from __future__ import annotations

from typing import Callable

from schemas.finding import Finding, FindingClassification

_GUARDRAIL_RULES = {
    "god-class",
    "sensitive-response-cache-control-missing",
    "weak-password-policy-validation",
    "registration-missing-registered-event",
}


def _classification_adjustment(classification: FindingClassification | str) -> float:
    key = classification.value if isinstance(classification, FindingClassification) else str(classification or "").strip().lower()
    if key == "advisory":
        return 0.03
    if key == "risk":
        return 0.01
    return 0.0


def enrich_findings_with_trust(
    findings: list[Finding],
    *,
    confidence_floor_resolver: Callable[[str], float] | None = None,
    profile_name: str = "startup",
    suppressed_count: int = 0,
    deduped_overlap_count: int = 0,
    filtered_by_confidence: int = 0,
) -> list[Finding]:
    """
    Mutates findings in-place with additive trust fields.
    Returns the same list for convenience.
    """
    resolver = confidence_floor_resolver or (lambda _: 0.0)

    for finding in findings:
        metadata = dict(getattr(finding, "metadata", {}) or {})
        decision_profile = metadata.get("decision_profile")
        if not isinstance(decision_profile, dict):
            decision_profile = {}

        signals = [str(s).strip() for s in (finding.evidence_signals or []) if str(s).strip()]
        top_signals = signals[:3]
        trigger_summary = str(
            decision_profile.get("decision_summary")
            or decision_profile.get("decision")
            or finding.description
            or ""
        ).strip()
        if len(trigger_summary) > 220:
            trigger_summary = trigger_summary[:217].rstrip() + "..."

        why_flagged = (
            f"Rule `{finding.rule_id}` matched at {finding.file}:{finding.line_start}. "
            f"Trigger: {trigger_summary or 'pattern and context match'}."
        )
        if top_signals:
            why_flagged += f" Signals: {', '.join(top_signals)}."

        base_floor = float(resolver(finding.rule_id) or 0.0)
        floor = max(0.0, min(1.0, base_floor + _classification_adjustment(getattr(finding, "classification", FindingClassification.ADVISORY))))
        conf = float(getattr(finding, "confidence", 0.0) or 0.0)

        not_ignored_parts = [
            f"confidence check passed ({conf:.2f} >= {floor:.2f})",
            f"context/profile gate passed ({profile_name})",
            "suppression filter check passed (no matching suppression rule)",
            "overlap dedupe ranking retained this finding",
        ]
        if finding.rule_id in _GUARDRAIL_RULES:
            not_ignored_parts.append("rule has false-positive guardrail tests")
        if filtered_by_confidence > 0:
            not_ignored_parts.append(f"{filtered_by_confidence} low-confidence findings were filtered this run")
        if suppressed_count > 0:
            not_ignored_parts.append(f"{suppressed_count} findings were suppressed this run")
        if deduped_overlap_count > 0:
            not_ignored_parts.append(f"{deduped_overlap_count} overlapping findings were deduplicated")

        why_not_ignored = "Not ignored because " + "; ".join(not_ignored_parts) + "."

        if not finding.why_flagged:
            finding.why_flagged = why_flagged
        if not finding.why_not_ignored:
            finding.why_not_ignored = why_not_ignored

        trust_payload = {
            "why_flagged": finding.why_flagged,
            "why_not_ignored": finding.why_not_ignored,
            "confidence": round(conf, 4),
            "confidence_floor": round(floor, 4),
            "top_evidence_signals": top_signals,
            "trigger_summary": trigger_summary,
            "profile": profile_name,
            "guardrail_rule": finding.rule_id in _GUARDRAIL_RULES,
            "suppressed_count_in_run": int(suppressed_count),
            "deduped_overlap_count_in_run": int(deduped_overlap_count),
            "filtered_by_confidence_in_run": int(filtered_by_confidence),
        }
        metadata["trust"] = trust_payload
        finding.metadata = metadata

    return findings
