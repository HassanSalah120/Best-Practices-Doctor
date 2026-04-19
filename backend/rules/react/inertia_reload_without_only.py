"""
Inertia Reload Without Only Rule

Detects `router.reload(...)` calls that do not scope payload fields via `only`/`except`.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class InertiaReloadWithoutOnlyRule(Rule):
    id = "inertia-reload-without-only"
    name = "Inertia Reload Without only/except"
    description = "Detects unscoped Inertia reload calls that can fetch unnecessary payload"
    category = Category.PERFORMANCE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _ALLOWLIST_PATH_MARKERS = (".test.", ".spec.", "__tests__", ".stories.")
    _RELOAD_PATTERN = re.compile(
        r"\b(?:router|Inertia|inertia)\.reload\s*\((?P<args>.*?)\)",
        re.IGNORECASE | re.DOTALL,
    )
    _ONLY_EXCEPT_PATTERN = re.compile(r"\b(?:only|except)\s*:", re.IGNORECASE)

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        text = content or ""
        if ".reload(" not in text:
            return []
        low_path = str(file_path or "").lower().replace("\\", "/")
        if any(marker in low_path for marker in self._ALLOWLIST_PATH_MARKERS):
            return []

        findings: list[Finding] = []
        max_findings_per_file = max(1, int(self.get_threshold("max_findings_per_file", 2)))

        for match in self._RELOAD_PATTERN.finditer(text):
            raw_args = str(match.group("args") or "").strip()
            pattern_name = ""

            if not raw_args:
                pattern_name = "reload-empty-args"
            elif raw_args.startswith("{"):
                if "..." in raw_args:
                    continue
                if self._ONLY_EXCEPT_PATTERN.search(raw_args):
                    continue
                pattern_name = "reload-object-without-only"
            else:
                # Variable/options object: unknown shape, skip to avoid false positives.
                continue

            line_number = text.count("\n", 0, match.start()) + 1
            findings.append(
                self.create_finding(
                    title="Inertia reload call is not payload-scoped",
                    context=pattern_name,
                    file=file_path,
                    line_start=line_number,
                    description=(
                        "Detected `router.reload(...)` without `only`/`except` scoping."
                    ),
                    why_it_matters=(
                        "Unscoped reloads can fetch larger payloads than needed and add avoidable latency."
                    ),
                    suggested_fix=(
                        "Provide `only` (or `except`) keys for partial reloads, for example:\n"
                        "`router.reload({ only: ['stats', 'filters'] })`."
                    ),
                    confidence=0.9,
                    tags=["inertia", "reload", "performance", "payload"],
                    evidence_signals=[f"pattern={pattern_name}"],
                    metadata={"decision_profile": {"pattern": pattern_name}},
                )
            )
            if len(findings) >= max_findings_per_file:
                break

        return findings
