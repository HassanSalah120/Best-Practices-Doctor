"""
React No Random Key Rule

Detects unstable React list keys built from random/time-based values.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


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
    _PATTERNS = [
        (
            "math-random",
            re.compile(r"\bkey\s*=\s*\{\s*Math\.random\s*\(\s*\)\s*\}", re.IGNORECASE),
        ),
        (
            "date-now",
            re.compile(r"\bkey\s*=\s*\{\s*Date\.now\s*\(\s*\)\s*\}", re.IGNORECASE),
        ),
        (
            "performance-now",
            re.compile(r"\bkey\s*=\s*\{\s*performance\.now\s*\(\s*\)\s*\}", re.IGNORECASE),
        ),
        (
            "crypto-random-uuid",
            re.compile(r"\bkey\s*=\s*\{\s*crypto\.randomUUID\s*\(\s*\)\s*\}", re.IGNORECASE),
        ),
        (
            "uuidv4-call",
            re.compile(r"\bkey\s*=\s*\{\s*uuidv?4?\s*\(\s*\)\s*\}", re.IGNORECASE),
        ),
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
        text = content or ""
        low_path = str(file_path or "").lower().replace("\\", "/")
        if any(marker in low_path for marker in self._ALLOWLIST_PATH_MARKERS):
            return []
        if "key" not in text or not any(token in text for token in ("Math.random", "Date.now", "randomUUID", "uuid")):
            return []

        max_findings_per_file = max(1, int(self.get_threshold("max_findings_per_file", 2)))
        findings: list[Finding] = []
        seen_lines: set[int] = set()

        for pattern_name, pattern in self._PATTERNS:
            for match in pattern.finditer(text):
                line_number = text.count("\n", 0, match.start()) + 1
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
                    )
                )
                if len(findings) >= max_findings_per_file:
                    return findings

        return findings
