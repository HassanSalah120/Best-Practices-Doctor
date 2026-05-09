"""
React No Random Key Rule

Detects unstable React list keys built from random/time-based values.
"""

from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


class ReactNoRandomKeyRule(Rule):
    id = "react-no-random-key"
    name = "Random Value Used As React Key"
    description = "Detects list keys generated from random/time-based values during render"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _ALLOWLIST_PATH_MARKERS = (".test.", ".spec.", "__tests__", ".stories.")
    _KEY_START = re.compile(r"\bkey\s*=\s*\{", re.IGNORECASE)
    _PATTERNS = [
        (
            "math-random",
            re.compile(r"\bMath\.random\s*\(\s*\)", re.IGNORECASE),
        ),
        (
            "date-now",
            re.compile(r"\bDate\.now\s*\(\s*\)", re.IGNORECASE),
        ),
        (
            "performance-now",
            re.compile(r"\bperformance\.now\s*\(\s*\)", re.IGNORECASE),
        ),
        (
            "crypto-random-uuid",
            re.compile(r"\bcrypto\.randomUUID\s*\(\s*\)", re.IGNORECASE),
        ),
        (
            "uuidv4-call",
            re.compile(r"\buuidv?4?\s*\(\s*\)", re.IGNORECASE),
        ),
    ]
    severity_weight = 0
    confidence = 'high'
    fix_suggestion = 'Refactor the component code to remove the random value used as react key pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
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
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'react-random-key'}

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
        low_path = str(file_path or "").lower().replace("\\", "/")
        if any(marker in low_path for marker in self._ALLOWLIST_PATH_MARKERS):
            return []
        if "key" not in text or not any(token in text for token in ("Math.random", "Date.now", "randomUUID", "uuid")):
            return []

        max_findings_per_file = max(1, int(self.get_threshold("max_findings_per_file", 2)))
        findings: list[Finding] = []
        seen_lines: set[int] = set()

        for key_match in self._KEY_START.finditer(text):
            expr_start = key_match.end()
            expr_end = self._find_jsx_expression_end(text, expr_start)
            if expr_end <= expr_start:
                continue
            key_expr = text[expr_start:expr_end]
            for pattern_name, pattern in self._PATTERNS:
                if not pattern.search(key_expr):
                    continue
                line_number = text.count("\n", 0, key_match.start()) + 1
                if line_number in seen_lines:
                    continue
                seen_lines.add(line_number)
                findings.append(
                    self.create_finding(
                        title="React key uses a random/time-based value",
                        context=pattern_name,
                        file=file_path,
                        line_start=line_number,
                        description=(
                            "Detected a React `key` generated from a random or time-based value. "
                            "This creates a new key identity on every render."
                        ),
                        why_it_matters=(
                            "Unstable keys force React to remount list items, lose local item state, "
                            "and cause unnecessary DOM work."
                        ),
                        suggested_fix=(
                            "Use a stable key from the item data (for example `item.id`). "
                            "If no stable id exists, generate it once when data is created and persist it."
                        ),
                        confidence=0.96,
                        tags=["react", "rendering", "keys", "stability"],
                        evidence_signals=[f"pattern={pattern_name}"],
                        metadata={"decision_profile": {"pattern": pattern_name}},
                    ),
                )
                if len(findings) >= max_findings_per_file:
                    return findings

        return findings

    def _find_jsx_expression_end(self, text: str, offset: int) -> int:
        depth = 1
        quote = ""
        escape = False
        index = offset
        while index < len(text):
            char = text[index]
            if escape:
                escape = False
                index += 1
                continue
            if quote:
                if char == "\\":
                    escape = True
                elif char == quote:
                    quote = ""
                index += 1
                continue
            if char in {"'", '"', "`"}:
                quote = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return index
            index += 1
        return -1
