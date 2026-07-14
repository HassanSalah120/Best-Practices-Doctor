"""
React No Array Index Key Rule

Detects JSX `key` props that use array index variables.
"""

from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


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
    severity_weight = 0
    confidence = 'high'
    fix_suggestion = 'Refactor the component code to remove the avoid array index as react key pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 3
    group = 'React Stability'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'react-array-index'}

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
        lines = content.splitlines()
        for line_number, raw_line in enumerate(lines, start=1):
            line = (raw_line or "").strip()
            if not line or line.startswith(("//", "/*", "*")):
                continue

            direct_match = self._DIRECT_PATTERN.search(line)
            if direct_match:
                if self._is_static_literal_map(lines, line_number, direct_match.group(1)) or self._is_positional_placeholder_map(lines, line_number):
                    continue
                findings.append(self._create_finding(file_path, line_number))
                continue

            template_match = self._TEMPLATE_PATTERN.search(line)
            if not template_match:
                continue
            placeholders = [expr.strip() for expr in self._PLACEHOLDER_PATTERN.findall(template_match.group("tpl") or "")]
            if not placeholders:
                continue
            if all(self._INDEX_EXPR.match(expr or "") for expr in placeholders):
                if len(placeholders) == 1 and self._is_static_literal_map(lines, line_number, placeholders[0]):
                    continue
                findings.append(self._create_finding(file_path, line_number))
        return findings

    def _is_static_literal_map(self, lines: list[str], line_number: int, key_var: str) -> bool:
        var = re.escape(str(key_var or "").strip())
        if not var:
            return False
        start = max(0, line_number - 5)
        end = min(len(lines), line_number + 2)
        window = "\n".join(lines[start:end])
        literal = r"(?:\d+|['\"][^'\"]+['\"]|`[^`]+`)"
        static_array_map = re.compile(
            rf"\[\s*{literal}(?:\s*,\s*{literal})*\s*\]\s*(?:as\s+const\s*)?\.map\(\s*(?:\(\s*{var}\s*\)|{var})\s*=>",
            re.IGNORECASE | re.DOTALL,
        )
        return bool(static_array_map.search(window))

    @staticmethod
    def _is_positional_placeholder_map(lines: list[str], line_number: int) -> bool:
        start = max(0, line_number - 6)
        end = min(len(lines), line_number + 2)
        window = "\n".join(lines[start:end])
        generated = re.search(r"(?:Array\.from\s*\(|new\s+Array\s*\(|\.fill\s*\()[\s\S]*?\.map\s*\(", window)
        placeholder = re.search(r"<(?:Skeleton|Placeholder|Spacer|Shimmer|Loading)[A-Za-z0-9_.]*\b", window, re.IGNORECASE)
        return bool(generated and placeholder)

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
