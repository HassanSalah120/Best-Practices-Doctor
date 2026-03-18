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

    _DIRECT_PATTERN = re.compile(r"\bkey\s*=\s*\{\s*(index|idx|i)\s*\}", re.IGNORECASE)
    _TEMPLATE_PATTERN = re.compile(r"\bkey\s*=\s*\{\s*`(?P<tpl>[^`]*)`\s*\}", re.IGNORECASE)
    _INDEX_EXPR = re.compile(r"^\s*(index|idx|i)\s*$", re.IGNORECASE)
    _PLACEHOLDER_PATTERN = re.compile(r"\$\{([^}]+)\}")

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
        findings: list[Finding] = []
        for line_number, raw_line in enumerate(content.splitlines(), start=1):
            line = (raw_line or "").strip()
            if not line or line.startswith(("//", "/*", "*")):
                continue

            if self._DIRECT_PATTERN.search(line):
                findings.append(self._create_finding(file_path, line_number))
                continue

            template_match = self._TEMPLATE_PATTERN.search(line)
            if not template_match:
                continue
            placeholders = [expr.strip() for expr in self._PLACEHOLDER_PATTERN.findall(template_match.group("tpl") or "")]
            if not placeholders:
                continue
            if all(self._INDEX_EXPR.match(expr or "") for expr in placeholders):
                findings.append(self._create_finding(file_path, line_number))
        return findings

    def _create_finding(self, file_path: str, line_number: int) -> Finding:
        return self.create_finding(
            title="Avoid array index as React key",
            context="array_index_key",
            file=file_path,
            line_start=line_number,
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
