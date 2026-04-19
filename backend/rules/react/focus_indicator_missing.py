"""
Focus Indicator Missing Rule (high-confidence only).
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class FocusIndicatorMissingRule(Rule):
    id = "focus-indicator-missing"
    name = "Focus Indicator Missing"
    description = "Detects explicit focus outline removal without visible replacement"
    category = Category.ACCESSIBILITY
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx", ".css"]

    _ALLOWLIST_PATHS = (
        "/tests/",
        "/test/",
        "/__tests__/",
        "/stories/",
        "/storybook/",
    )
    _TAG_RE = re.compile(r"<(?P<tag>button|a|input|select|textarea|summary)\b(?P<attrs>[^>]*)>", re.IGNORECASE | re.DOTALL)
    _REMOVAL_RE = re.compile(r"\b(?:outline-none|outline-0|focus:outline-none|focus-visible:outline-none|ring-0)\b", re.IGNORECASE)
    _FOCUS_REPLACEMENT_RE = re.compile(
        r"(focus(?:-visible)?:ring-(?!0\b)|focus(?:-visible)?:outline-(?!none\b|0\b)|focus(?:-visible)?:border-|focus(?:-visible)?:shadow-|:focus-visible\s*\{|:focus\s*\{)",
        re.IGNORECASE,
    )

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
        if self._is_allowlisted_path(file_path):
            return []

        findings: list[Finding] = []
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 3)))
        text = content or ""

        for m in self._TAG_RE.finditer(text):
            if len(findings) >= max_findings:
                break
            attrs = m.group("attrs") or ""
            if not self._REMOVAL_RE.search(attrs):
                continue
            if self._FOCUS_REPLACEMENT_RE.search(attrs):
                continue
            line = text.count("\n", 0, m.start()) + 1
            tag = (m.group("tag") or "").lower()
            findings.append(
                self.create_finding(
                    title="Focus indicator removed without replacement",
                    context=f"{file_path}:{line}:{tag}",
                    file=file_path,
                    line_start=line,
                    description=(
                        f"`<{tag}>` removes default focus outline but does not provide an alternative visible focus style."
                    ),
                    why_it_matters=(
                        "WCAG focus visibility requires keyboard users to clearly see where focus is."
                    ),
                    suggested_fix=(
                        "Add explicit focus-visible styling when removing outlines, e.g. "
                        "`focus-visible:ring-2 focus-visible:ring-offset-2`."
                    ),
                    tags=["a11y", "wcag", "focus", "keyboard"],
                    confidence=0.95,
                    evidence_signals=[
                        "focus_outline_removed=true",
                        "focus_replacement_missing=true",
                    ],
                )
            )

        return findings

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)
