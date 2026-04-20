"""
Fix intelligence helpers.

Shared logic for:
- fix strategy classification
- deterministic confidence scoring
- project-fit rationale text
"""

from __future__ import annotations

from typing import Any, Literal

from schemas.finding import Finding

FixStrategy = Literal["safe", "risky", "refactor"]

_SAFE_RULES = {
    "no-log-debug-in-app",
}

_RISKY_RULES = {
    "env-outside-config",
    "prefer-imports",
    "react-no-array-index-key",
}

_REFACTOR_RULES = {
    "missing-form-request",
    "hooks-in-conditional-or-loop",
    "no-dangerously-set-inner-html",
    "missing-key-on-list-render",
}


def get_fix_strategy(rule_id: str) -> FixStrategy:
    rid = str(rule_id or "").strip().lower()
    if rid in _SAFE_RULES:
        return "safe"
    if rid in _REFACTOR_RULES:
        return "refactor"
    if rid in _RISKY_RULES:
        return "risky"
    return "risky"


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _infer_project_fit(
    finding: Finding,
    project_context: dict[str, Any] | None,
) -> tuple[float, str]:
    profile = {}
    if isinstance(getattr(finding, "metadata", None), dict):
        candidate = finding.metadata.get("decision_profile")
        if isinstance(candidate, dict):
            profile = candidate

    ctx = dict(project_context or {})
    framework = str(
        profile.get("backend_framework")
        or ctx.get("backend_framework")
        or "unknown"
    ).strip().lower()
    project_type = str(
        profile.get("project_type")
        or profile.get("project_business_context")
        or ctx.get("project_type")
        or ctx.get("project_business_context")
        or "unknown"
    ).strip().lower()

    rid = str(finding.rule_id or "").strip().lower()
    category = str(getattr(getattr(finding, "category", None), "value", finding.category) or "").strip().lower()

    is_react_rule = "react" in category or rid.startswith("react-") or "jsx" in rid or "inertia-" in rid
    is_laravel_rule = "laravel" in category or rid in {
        "missing-form-request",
        "no-log-debug-in-app",
        "env-outside-config",
    } or "route" in rid or "migration" in rid

    score = 0.6
    reasons: list[str] = []

    if is_react_rule:
        if framework in {"react", "inertia", "laravel-inertia"}:
            score = 0.9
            reasons.append(f"framework={framework}")
        else:
            score = 0.72
            reasons.append("frontend-pattern-inference")
    elif is_laravel_rule:
        if "laravel" in framework:
            score = 0.9
            reasons.append(f"framework={framework}")
        else:
            score = 0.74
            reasons.append("backend-pattern-inference")
    else:
        score = 0.7
        reasons.append("generic-rule-fit")

    caps = profile.get("capabilities")
    if isinstance(caps, list):
        cap_set = {str(x).strip().lower() for x in caps if str(x).strip()}
        if "public_surface" in cap_set and "security" in category:
            score += 0.05
            reasons.append("public_surface+security")
        if "realtime" in cap_set and ("listener" in rid or "broadcast" in rid):
            score += 0.04
            reasons.append("realtime-capability")

    score = _clamp01(score)
    summary = f"Project fit uses framework={framework or 'unknown'} and project_type={project_type or 'unknown'}"
    if reasons:
        summary += f" ({', '.join(reasons[:3])})"
    return (score, summary)


def evaluate_fix_confidence(
    finding: Finding,
    original_code: str,
    fixed_code: str,
    strategy: FixStrategy,
    project_context: dict[str, Any] | None = None,
) -> tuple[float, dict[str, float], str, str]:
    """
    Deterministic confidence model:
    confidence = 0.35*pattern_match + 0.25*edit_locality + 0.2*syntax_safety + 0.2*project_fit
    """
    original = str(original_code or "")
    fixed = str(fixed_code or "")

    pattern_match = 0.95 if fixed and fixed != original else 0.2

    original_lines = max(1, len(original.splitlines()))
    fixed_lines = max(1, len(fixed.splitlines()))
    line_delta = abs(fixed_lines - original_lines)
    locality_penalty = min(0.6, line_delta / 20.0)
    edit_locality = _clamp01(0.95 - locality_penalty)

    syntax_safety = {
        "safe": 0.95,
        "risky": 0.72,
        "refactor": 0.58,
    }.get(strategy, 0.7)

    project_fit, fit_reason = _infer_project_fit(finding, project_context)

    confidence = (
        0.35 * pattern_match
        + 0.25 * edit_locality
        + 0.20 * syntax_safety
        + 0.20 * project_fit
    )
    confidence = round(_clamp01(confidence), 4)

    breakdown = {
        "pattern_match": round(pattern_match, 4),
        "edit_locality": round(edit_locality, 4),
        "syntax_safety": round(syntax_safety, 4),
        "project_fit": round(project_fit, 4),
    }

    risk_notes = {
        "safe": "Low risk patch; localized edit and high syntax safety.",
        "risky": "Moderate risk; review surrounding code and runtime behavior before applying.",
        "refactor": "Refactor-level change; requires human review and broader regression checks.",
    }.get(strategy, "Manual review recommended.")

    return (confidence, breakdown, fit_reason, risk_notes)
