"""
React No Props Mutation Rule

Detects direct mutation of the `props` object in React component files.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class ReactNoPropsMutationRule(Rule):
    id = "react-no-props-mutation"
    name = "Props Object Mutation"
    description = "Detects direct mutation of React props"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.HIGH
    default_classification = FindingClassification.DEFECT
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _ALLOWLIST_PATH_MARKERS = (".test.", ".spec.", "__tests__", ".stories.", "/types/", ".d.ts")
    _MUTATION_PATTERNS = [
        (
            "props-dot-assignment",
            re.compile(r"\bprops(?:\.[A-Za-z_][A-Za-z0-9_]*)+\s*(?:=|\+=|-=|\*=|/=|%=|\+\+|--)", re.IGNORECASE),
        ),
        (
            "props-bracket-assignment",
            re.compile(r"\bprops\s*\[\s*['\"][^'\"]+['\"]\s*\]\s*(?:=|\+=|-=|\*=|/=|%=|\+\+|--)", re.IGNORECASE),
        ),
        (
            "object-assign-props",
            re.compile(r"\bObject\.assign\s*\(\s*props\s*,", re.IGNORECASE),
        ),
        (
            "define-property-props",
            re.compile(r"\bObject\.defineProperty\s*\(\s*props\s*,", re.IGNORECASE),
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
        if "props" not in text:
            return []
        low_path = str(file_path or "").lower().replace("\\", "/")
        if any(marker in low_path for marker in self._ALLOWLIST_PATH_MARKERS):
            return []

        require_component_signal = bool(self.get_threshold("require_component_signal", True))
        if require_component_signal and not self._looks_like_component_content(text, low_path):
            return []

        max_findings_per_file = max(1, int(self.get_threshold("max_findings_per_file", 2)))
        findings: list[Finding] = []
        seen_lines: set[int] = set()

        for pattern_name, pattern in self._MUTATION_PATTERNS:
            for match in pattern.finditer(text):
                line_number = text.count("\n", 0, match.start()) + 1
                if line_number in seen_lines:
                    continue
                seen_lines.add(line_number)
                findings.append(
                    self.create_finding(
                        title="Props object appears to be mutated",
                        context=pattern_name,
                        file=file_path,
                        line_start=line_number,
                        description=(
                            "Detected direct mutation of `props`. React props should be treated as immutable inputs."
                        ),
                        why_it_matters=(
                            "Mutating props breaks one-way data flow and can create stale UI state and hard-to-debug rendering bugs."
                        ),
                        suggested_fix=(
                            "Create a local copy before mutation (or derive new values immutably), and keep `props` read-only."
                        ),
                        confidence=0.92,
                        tags=["react", "props", "immutability", "correctness"],
                        evidence_signals=[f"pattern={pattern_name}"],
                        metadata={"decision_profile": {"pattern": pattern_name}},
                    )
                )
                if len(findings) >= max_findings_per_file:
                    return findings

        return findings

    def _looks_like_component_content(self, content: str, low_path: str) -> bool:
        if low_path.endswith(".tsx") or low_path.endswith(".jsx"):
            return True
        if any(token in low_path for token in ("/components/", "/pages/", "/layouts/", "/screens/")):
            return True
        low = content.lower()
        if "return <" in low:
            return True
        return "jsx" in low and "props" in low
