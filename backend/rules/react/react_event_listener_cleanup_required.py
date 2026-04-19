"""
React Event Listener Cleanup Required Rule

Detects `addEventListener` inside `useEffect` blocks without matching cleanup.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class ReactEventListenerCleanupRequiredRule(Rule):
    id = "react-event-listener-cleanup-required"
    name = "Event Listener Cleanup Required"
    description = "Detects addEventListener in useEffect without removeEventListener cleanup"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _ALLOWLIST_PATH_MARKERS = (".test.", ".spec.", "__tests__", ".stories.")
    _USE_EFFECT_PATTERN = re.compile(r"\buseEffect\s*\(", re.IGNORECASE)
    _ADD_EVENT_PATTERN = re.compile(r"\baddEventListener\s*\(", re.IGNORECASE)
    _REMOVE_EVENT_PATTERN = re.compile(r"\bremoveEventListener\s*\(", re.IGNORECASE)
    _ABORT_SIGNAL_PATTERN = re.compile(r"\bsignal\s*:", re.IGNORECASE)

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
        if "addEventListener" not in text or "useEffect" not in text:
            return []
        low_path = str(file_path or "").lower().replace("\\", "/")
        if any(marker in low_path for marker in self._ALLOWLIST_PATH_MARKERS):
            return []

        findings: list[Finding] = []
        max_findings_per_file = max(1, int(self.get_threshold("max_findings_per_file", 2)))

        for start, window in self._iter_useeffect_blocks(text):
            if not self._ADD_EVENT_PATTERN.search(window):
                continue
            if self._REMOVE_EVENT_PATTERN.search(window):
                continue
            # If signal-based listener lifecycle is used, skip to avoid false positives.
            if self._ABORT_SIGNAL_PATTERN.search(window) and "abort" in window.lower():
                continue

            line_number = text.count("\n", 0, start) + 1
            findings.append(
                self.create_finding(
                    title="useEffect adds event listener without cleanup",
                    context="addEventListener-without-removeEventListener",
                    file=file_path,
                    line_start=line_number,
                    description=(
                        "Detected `addEventListener` inside `useEffect` without a matching cleanup."
                    ),
                    why_it_matters=(
                        "Missing listener cleanup can leak handlers and trigger duplicate callbacks after rerenders/unmounts."
                    ),
                    suggested_fix=(
                        "Return a cleanup function from `useEffect` and remove the same listener:\n"
                        "`return () => target.removeEventListener(event, handler);`"
                    ),
                    confidence=0.9,
                    tags=["react", "useeffect", "events", "cleanup"],
                    evidence_signals=["effect_contains=addEventListener", "cleanup_contains=removeEventListener:false"],
                    metadata={"decision_profile": {"signal_based_cleanup": False}},
                )
            )
            if len(findings) >= max_findings_per_file:
                break

        return findings

    def _iter_useeffect_blocks(self, text: str) -> list[tuple[int, str]]:
        blocks: list[tuple[int, str]] = []
        for match in self._USE_EFFECT_PATTERN.finditer(text):
            paren_start = text.find("(", match.start())
            if paren_start == -1:
                continue
            paren_end = self._find_matching_paren(text, paren_start)
            if paren_end == -1:
                window = text[match.start() : match.start() + 4000]
            else:
                window = text[match.start() : paren_end + 1]
            blocks.append((match.start(), window))
        return blocks

    def _find_matching_paren(self, text: str, start: int) -> int:
        depth = 0
        in_single = False
        in_double = False
        in_backtick = False
        in_line_comment = False
        in_block_comment = False
        escaped = False

        for i in range(start, len(text)):
            ch = text[i]
            nxt = text[i + 1] if i + 1 < len(text) else ""

            if in_line_comment:
                if ch == "\n":
                    in_line_comment = False
                continue
            if in_block_comment:
                if ch == "*" and nxt == "/":
                    in_block_comment = False
                continue
            if escaped:
                escaped = False
                continue

            if ch == "\\" and (in_single or in_double or in_backtick):
                escaped = True
                continue

            if in_single:
                if ch == "'":
                    in_single = False
                continue
            if in_double:
                if ch == '"':
                    in_double = False
                continue
            if in_backtick:
                if ch == "`":
                    in_backtick = False
                continue

            if ch == "/" and nxt == "/":
                in_line_comment = True
                continue
            if ch == "/" and nxt == "*":
                in_block_comment = True
                continue

            if ch == "'":
                in_single = True
                continue
            if ch == '"':
                in_double = True
                continue
            if ch == "`":
                in_backtick = True
                continue

            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return i

        return -1
