"""
React No Array Index Key Rule

Detects JSX `key` props that use array index variables.
"""

from __future__ import annotations

import re

from core.regex_scan import regex_scan
from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class NoArrayIndexKeyRule(Rule):
    id = "react-no-array-index-key"
    name = "Avoid Array Index as React Key"
    description = "Detects unstable React key props that use array index variables"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _PATTERNS = [
        re.compile(r"\bkey\s*=\s*\{\s*(index|idx|i)\s*\}", re.IGNORECASE),
        re.compile(r"\bkey\s*=\s*\{\s*`[^`]*\$\{\s*(index|idx|i)\s*\}[^`]*`\s*\}", re.IGNORECASE),
    ]

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
        hits = regex_scan(content, self._PATTERNS)
        findings: list[Finding] = []
        for h in hits:
            line = (h.line or "").strip()
            if not line or line.startswith(("//", "/*", "*")):
                continue
            findings.append(
                self.create_finding(
                    title="Avoid array index as React key",
                    context="array_index_key",
                    file=file_path,
                    line_start=h.line_number,
                    description=(
                        "Detected JSX key prop based on array index. "
                        "Use a stable identifier from data (e.g., `item.id`) instead."
                    ),
                    why_it_matters=(
                        "Index-based keys break React reconciliation when list order changes. "
                        "This causes subtle UI bugs (lost input focus/state) and unnecessary re-renders."
                    ),
                    suggested_fix=(
                        "Use a stable unique key from the item itself, such as `key={item.id}`.\n"
                        "If data lacks a stable id, generate one when creating the data, not during render."
                    ),
                    tags=["react", "performance", "reconciliation", "list-rendering"],
                    confidence=0.85,
                )
            )
        return findings
