"""
React Timer Cleanup Required Rule

Detects timer APIs used inside `useEffect` without matching cleanup.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class ReactTimerCleanupRequiredRule(Rule):
    id = "react-timer-cleanup-required"
    name = "Timer Cleanup Required"
    description = "Detects timer APIs in useEffect without proper cleanup"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _ALLOWLIST_PATH_MARKERS = (".test.", ".spec.", "__tests__", ".stories.")
    _USE_EFFECT_PATTERN = re.compile(r"\buseEffect\s*\(", re.IGNORECASE)
    _SET_INTERVAL = re.compile(r"\bsetInterval\s*\(", re.IGNORECASE)
    _CLEAR_INTERVAL = re.compile(r"\bclearInterval\s*\(", re.IGNORECASE)
    _SET_TIMEOUT = re.compile(r"\bsetTimeout\s*\(", re.IGNORECASE)
    _CLEAR_TIMEOUT = re.compile(r"\bclearTimeout\s*\(", re.IGNORECASE)
    _RAF = re.compile(r"\brequestAnimationFrame\s*\(", re.IGNORECASE)
    _CANCEL_RAF = re.compile(r"\bcancelAnimationFrame\s*\(", re.IGNORECASE)

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
        if "useEffect" not in text:
            return []
        low_path = str(file_path or "").lower().replace("\\", "/")
        if any(marker in low_path for marker in self._ALLOWLIST_PATH_MARKERS):
            return []

        include_set_timeout = bool(self.get_threshold("include_set_timeout", False))
        max_findings_per_file = max(1, int(self.get_threshold("max_findings_per_file", 2)))
        findings: list[Finding] = []

        for start, window in self._iter_useeffect_blocks(text):
            missing: list[str] = []
            if self._SET_INTERVAL.search(window) and not self._CLEAR_INTERVAL.search(window):
                missing.append("setInterval/clearInterval")
            if include_set_timeout and self._SET_TIMEOUT.search(window) and not self._CLEAR_TIMEOUT.search(window):
                missing.append("setTimeout/clearTimeout")
            if self._RAF.search(window) and not self._CANCEL_RAF.search(window):
                missing.append("requestAnimationFrame/cancelAnimationFrame")
            if not missing:
                continue

            line_number = text.count("\n", 0, start) + 1
            findings.append(
                self.create_finding(
                    title="useEffect timer setup appears to miss cleanup",
                    context="timer-cleanup-missing",
                    file=file_path,
                    line_start=line_number,
                    description=(
                        "Detected timer setup in `useEffect` without matching cleanup: "
                        f"{', '.join(missing)}."
                    ),
                    why_it_matters=(
                        "Uncleared timers can leak work, update stale state after unmount, and produce flaky UI behavior."
                    ),
                    suggested_fix=(
                        "Store timer handles and clear them in the effect cleanup function."
                    ),
                    confidence=0.9,
                    tags=["react", "useeffect", "timers", "cleanup"],
                    evidence_signals=[f"missing_pairs={','.join(missing)}", f"include_set_timeout={int(include_set_timeout)}"],
                    metadata={"decision_profile": {"missing_pairs": missing, "include_set_timeout": include_set_timeout}},
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
