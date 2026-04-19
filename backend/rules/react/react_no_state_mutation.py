"""
React No State Mutation Rule

Detects direct mutation of values returned by `useState`.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class ReactNoStateMutationRule(Rule):
    id = "react-no-state-mutation"
    name = "State Variable Mutation"
    description = "Detects direct mutation of React state variables"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.HIGH
    default_classification = FindingClassification.DEFECT
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _ALLOWLIST_PATH_MARKERS = (".test.", ".spec.", "__tests__", ".stories.")
    _STATE_DECLARATION = re.compile(
        r"\bconst\s*\[\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*set[A-Za-z_][A-Za-z0-9_]*\s*\]\s*=\s*useState(?:<[^>]+>)?\s*\(",
        re.MULTILINE,
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
        text = content or ""
        low_path = str(file_path or "").lower().replace("\\", "/")
        if any(marker in low_path for marker in self._ALLOWLIST_PATH_MARKERS):
            return []
        if "useState" not in text:
            return []

        max_state_vars = max(1, int(self.get_threshold("max_state_vars", 12)))
        state_vars = self._extract_state_vars(text)[:max_state_vars]
        if not state_vars:
            return []

        max_findings_per_file = max(1, int(self.get_threshold("max_findings_per_file", 3)))
        findings: list[Finding] = []
        seen_lines: set[int] = set()

        for state_var in state_vars:
            for pattern_name, pattern in self._mutation_patterns_for(state_var):
                for match in pattern.finditer(text):
                    line_number = text.count("\n", 0, match.start()) + 1
                    if line_number in seen_lines:
                        continue
                    seen_lines.add(line_number)
                    findings.append(
                        self.create_finding(
                            title="State variable appears to be mutated directly",
                            context=f"{state_var}:{pattern_name}",
                            file=file_path,
                            line_start=line_number,
                            description=(
                                f"Detected direct mutation of `{state_var}` returned from `useState`."
                            ),
                            why_it_matters=(
                                "Direct mutation of state can prevent React from detecting updates and cause stale renders."
                            ),
                            suggested_fix=(
                                "Use the state setter with immutable updates, for example:\n"
                                "`setState(prev => [...prev, item])` or `setState(prev => ({ ...prev, key: value }))`."
                            ),
                            confidence=0.93,
                            tags=["react", "state", "immutability", "correctness"],
                            evidence_signals=[f"state_var={state_var}", f"pattern={pattern_name}"],
                            metadata={"decision_profile": {"state_var": state_var, "pattern": pattern_name}},
                        )
                    )
                    if len(findings) >= max_findings_per_file:
                        return findings

        return findings

    def _extract_state_vars(self, text: str) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for match in self._STATE_DECLARATION.finditer(text):
            name = str(match.group(1) or "").strip()
            if not name or name in seen:
                continue
            seen.add(name)
            out.append(name)
        return out

    def _mutation_patterns_for(self, state_var: str) -> list[tuple[str, re.Pattern[str]]]:
        escaped = re.escape(state_var)
        return [
            (
                "dot-assignment",
                re.compile(
                    rf"\b{escaped}\.[A-Za-z_][A-Za-z0-9_]*\s*(?:\+\+|--|\+=|-=|\*=|/=|%=|=(?!=))",
                    re.IGNORECASE,
                ),
            ),
            (
                "bracket-assignment",
                re.compile(
                    rf"\b{escaped}\s*\[\s*[^\]]+\s*\]\s*(?:\+\+|--|\+=|-=|\*=|/=|%=|=(?!=))",
                    re.IGNORECASE,
                ),
            ),
            (
                "array-mutator",
                re.compile(
                    rf"\b{escaped}\.(?:push|pop|shift|unshift|splice|sort|reverse|copyWithin|fill)\s*\(",
                    re.IGNORECASE,
                ),
            ),
        ]
