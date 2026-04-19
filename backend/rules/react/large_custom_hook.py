"""
Large Custom Hook Rule

Flags oversized custom hooks with high orchestration density.
"""

from __future__ import annotations

import os
import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Category, Finding, FindingClassification, Severity
from rules.base import Rule


class LargeCustomHookRule(Rule):
    id = "large-custom-hook"
    name = "Large Custom Hook"
    description = "Detects oversized custom hooks that likely need decomposition"
    category = Category.MAINTAINABILITY
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _ALLOWLIST_PATH_MARKERS = (".test.", ".spec.", "__tests__", ".stories.")
    _HOOK_PATH_MARKER = re.compile(r"/hooks?/|(^|/)use[A-Z][A-Za-z0-9_]*\.(t|j)sx?$", re.IGNORECASE)
    _LOGIC_SIGNAL_PATTERNS = [
        re.compile(r"\buse(State|Reducer|Effect|Memo|Callback|Ref)\s*\(", re.IGNORECASE),
        re.compile(r"\bfetch\s*\(", re.IGNORECASE),
        re.compile(r"\baxios\.", re.IGNORECASE),
        re.compile(r"\bnew\s+WebSocket\s*\(", re.IGNORECASE),
        re.compile(r"\bsetInterval\s*\(", re.IGNORECASE),
        re.compile(r"\bsetTimeout\s*\(", re.IGNORECASE),
        re.compile(r"\bdispatch\s*\(", re.IGNORECASE),
    ]
    _FUNCTION_DECL = re.compile(
        r"\b(?:export\s+)?function\s+(use[A-Z][A-Za-z0-9_]*)\s*\(",
        re.IGNORECASE,
    )
    _FUNCTION_ARROW = re.compile(
        r"\b(?:export\s+)?const\s+(use[A-Z][A-Za-z0-9_]*)\s*=\s*(?:async\s*)?\(",
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
        normalized_path = (file_path or "").replace("\\", "/").lower()
        if any(marker in normalized_path for marker in self._ALLOWLIST_PATH_MARKERS):
            return []
        if not self._HOOK_PATH_MARKER.search(normalized_path):
            if not os.path.basename(normalized_path).startswith("use"):
                return []

        has_hook_name = bool(
            self._FUNCTION_DECL.search(content or "")
            or self._FUNCTION_ARROW.search(content or "")
            or os.path.basename(normalized_path).startswith("use")
        )
        if not has_hook_name:
            return []

        max_loc = max(120, int(self.get_threshold("max_loc", 280)))
        min_overflow = max(0, int(self.get_threshold("min_overflow_lines", 30)))
        min_logic_signals = max(2, int(self.get_threshold("min_logic_signals", 4)))

        loc = self._logical_loc(content or "")
        if loc < (max_loc + min_overflow):
            return []

        logic_signals = self._logic_signal_count(content or "")
        if logic_signals < min_logic_signals:
            return []

        first_line = 1
        finding = self.create_finding(
            title="Custom hook is too large",
            context=f"{file_path} ({loc} LOC)",
            file=file_path,
            line_start=first_line,
            description=(
                f"This custom hook has {loc} logical lines and strong orchestration signals ({logic_signals}). "
                "It likely mixes multiple concerns."
            ),
            why_it_matters=(
                "Large hooks become hard to test and evolve. Splitting state orchestration, effects, "
                "and domain operations into smaller hooks improves readability and reliability."
            ),
            suggested_fix=(
                "Extract cohesive sub-hooks by responsibility (state model, data loading, event wiring, UI adapters), "
                "then compose them in this hook."
            ),
            confidence=0.84,
            tags=["react", "hooks", "maintainability", "srp"],
            evidence_signals=[
                f"loc={loc}",
                f"max_loc={max_loc}",
                f"logic_signals={logic_signals}",
            ],
            metadata={
                "decision_profile": {
                    "loc": loc,
                    "max_loc": max_loc,
                    "min_overflow_lines": min_overflow,
                    "logic_signals": logic_signals,
                    "min_logic_signals": min_logic_signals,
                }
            },
        )
        return [finding]

    def _logical_loc(self, text: str) -> int:
        count = 0
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue
            count += 1
        return count

    def _logic_signal_count(self, text: str) -> int:
        matches = 0
        for pattern in self._LOGIC_SIGNAL_PATTERNS:
            matches += len(pattern.findall(text))
        return matches
