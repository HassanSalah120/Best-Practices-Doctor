"""
Missing null guard after relation load rule.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class MissingNullGuardAfterRelationLoadRule(Rule):
    id = "missing-null-guard-after-relation-load"
    name = "Missing Null Guard After Relation Load"
    description = "Detects relation loads followed by relation usage without a null guard"
    category = Category.VALIDATION
    default_severity = Severity.MEDIUM
    type = "regex"
    regex_file_extensions = [".php"]
    severity_weight = 5
    confidence = "medium"
    fix_suggestion = (
        "After loadMissing(), always null-check the relation before use. Orphaned records can exist in production "
        "databases. Use abort_if(! $model->relation, 422) or throw explicitly."
    )
    examples = {
        "bad": "$event->loadMissing('clinic');\n$this->handlerRegistry->process($event);",
        "good": "$event->loadMissing('clinic');\nabort_if(! $event->clinic, 422);\n$this->handlerRegistry->process($event);",
    }
    priority = 3
    group = "Data Access"
    applies_to = ["service", "controller", "job"]
    references = []
    related_rules = ["missing-transaction-on-critical-flow"]
    false_positive_notes = (
        "May false-positive if the model has a required relation enforced by a database constraint. Still recommended "
        "to add explicit null guard for clarity."
    )
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "quality", "concern": "relation-null-guard"}

    _LOAD_RE = re.compile(
        r"(?P<model>\$\w+)->load(?:Missing)?\s*\(\s*['\"](?P<relation>clinic|organization|tenant|user|company)['\"]",
        re.IGNORECASE,
    )

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._is_test_file(file_path) or "withDefault(" in content:
            return []

        lines = content.splitlines()
        findings: list[Finding] = []
        for idx, line_text in enumerate(lines):
            match = self._LOAD_RE.search(line_text)
            if not match:
                continue
            model = match.group("model")
            relation = match.group("relation")
            window_lines = lines[idx + 1:idx + 11]
            window = "\n".join(window_lines)
            usage_match = re.search(rf"{re.escape(model)}->{re.escape(relation)}\b", window)
            if not usage_match:
                continue
            between = window[:usage_match.start()]
            if self._has_null_guard(model, relation, between + window_lines[0] if window_lines else between):
                continue
            findings.append(
                self.create_finding(
                    title="Loaded relation is used without a null guard",
                    file=file_path,
                    line_start=idx + 1,
                    line_end=idx + 1,
                    context=f"{model}->{relation}",
                    description=(
                        f"{model}->loadMissing('{relation}') is followed by {model}->{relation} usage without an obvious null guard."
                    ),
                    why_it_matters=(
                        "Production data can contain orphaned rows. A missing relation guard turns that data issue into "
                        "a runtime crash with unclear handling."
                    ),
                    suggested_fix=self.fix_suggestion,
                    tags=["laravel", "quality", "data-integrity", "relations"],
                    confidence=0.72,
                )
            )
        return findings

    @staticmethod
    def _has_null_guard(model: str, relation: str, text: str) -> bool:
        relation_ref = rf"{re.escape(model)}->{re.escape(relation)}"
        return bool(
            re.search(rf"(if|abort_if)\s*\(\s*!\s*{relation_ref}", text)
            or re.search(rf"abort_unless\s*\(\s*{relation_ref}", text)
            or re.search(rf"isset\s*\(\s*{relation_ref}", text)
            or re.search(rf"{relation_ref}\s*\?\?", text)
            or (relation in text and "throw" in text)
        )

    @staticmethod
    def _is_test_file(file_path: str) -> bool:
        low = file_path.lower().replace("\\", "/")
        return "/tests/" in low or low.endswith("test.php")
