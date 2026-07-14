"""Static execution contracts for the shipped rule profiles.

The analyzer filters findings after rules run. This module catches the easy-to-
miss configuration error where every literal confidence emitted by a rule is
below the active profile's confidence floor, making an enabled rule unreachable.
"""
from __future__ import annotations

import ast
import inspect
import textwrap
from dataclasses import dataclass

from core.ruleset import Ruleset
from rules.base import Rule
from schemas.finding import FindingClassification


@dataclass(frozen=True)
class UnreachableRule:
    rule_id: str
    confidence_ceiling: float
    required_floor: float


_PROFILE_FLOORS = {"startup": 0.65, "balanced": 0.55, "strict": 0.45}
_CLASSIFICATION_ADJUSTMENTS = {
    "startup": {"defect": 0.0, "risk": 0.02, "advisory": 0.05},
    "balanced": {"defect": 0.0, "risk": 0.01, "advisory": 0.03},
    "strict": {"defect": 0.0, "risk": 0.0, "advisory": 0.01},
}


def find_statically_unreachable_rules(
    runtime_rules: dict[str, type[Rule]],
    ruleset: Ruleset,
) -> list[UnreachableRule]:
    """Return enabled rules whose literal findings cannot pass the profile.

    Rules with computed confidence/classification or indirect finding factories
    are deliberately treated as unknown, avoiding speculative failures.
    """
    unreachable: list[UnreachableRule] = []
    profile = str(ruleset.name or "balanced").strip().lower()
    base_floor = _PROFILE_FLOORS.get(profile, _PROFILE_FLOORS["balanced"])
    adjustments = _CLASSIFICATION_ADJUSTMENTS.get(
        profile,
        _CLASSIFICATION_ADJUSTMENTS["balanced"],
    )

    for rule_id, rule_class in runtime_rules.items():
        config = ruleset.get_rule_config(rule_id)
        if not config.enabled:
            continue
        calls = _literal_finding_contracts(rule_class)
        if not calls:
            continue

        configured_floor = base_floor
        has_explicit_floor = False
        raw_floor = (config.thresholds or {}).get("min_confidence")
        if raw_floor is not None:
            try:
                configured_floor = max(0.0, min(1.0, float(raw_floor)))
                has_explicit_floor = True
            except (TypeError, ValueError):
                pass

        rule = rule_class(config)
        margins: list[tuple[float, float, float]] = []
        for confidence, classification_name in calls:
            if confidence is None or classification_name == "dynamic":
                margins = []
                break
            if classification_name:
                classification = classification_name
            else:
                classification = rule._default_finding_classification(rule.severity).value
            adjustment = 0.0 if has_explicit_floor else adjustments.get(classification, 0.0)
            floor = min(1.0, configured_floor + adjustment)
            margins.append((confidence - floor, confidence, floor))

        if margins and max(item[0] for item in margins) < -1e-9:
            best = max(margins, key=lambda item: item[0])
            unreachable.append(UnreachableRule(rule_id, best[1], best[2]))

    return sorted(unreachable, key=lambda item: item.rule_id)


def _literal_finding_contracts(
    rule_class: type[Rule],
) -> list[tuple[float | None, str | None]]:
    try:
        tree = ast.parse(textwrap.dedent(inspect.getsource(rule_class)))
    except (OSError, TypeError, SyntaxError, IndentationError):
        return []

    calls: list[tuple[float | None, str | None]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_create_finding_call(node.func):
            continue
        keywords = {kw.arg: kw.value for kw in node.keywords if kw.arg}
        confidence_node = keywords.get("confidence")
        confidence = 1.0 if confidence_node is None else _literal_float(confidence_node)
        classification = _classification_name(keywords.get("classification"))
        calls.append((confidence, classification))
    return calls


def _is_create_finding_call(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "create_finding"
    ) or (isinstance(node, ast.Name) and node.id == "create_finding")


def _literal_float(node: ast.expr) -> float | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return float(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        value = _literal_float(node.operand)
        return -value if value is not None else None
    return None


def _classification_name(node: ast.expr | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        if node.value.id == "FindingClassification":
            try:
                return FindingClassification[node.attr].value
            except KeyError:
                return "dynamic"
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        value = node.value.strip().lower()
        if value in {item.value for item in FindingClassification}:
            return value
    return "dynamic"
