"""
UseEffect Fetch Without Abort Rule

Detects fetch calls inside useEffect that do not show abort or cleanup handling.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class UseEffectFetchWithoutAbortRule(Rule):
    id = "react-useeffect-fetch-without-abort"
    name = "UseEffect Fetch Without Abort"
    description = "Detects fetch in useEffect without abort or cleanup handling"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _USE_EFFECT = re.compile(r"useEffect\s*\(", re.IGNORECASE)

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
        findings: list[Finding] = []
        for match in self._USE_EFFECT.finditer(text):
            window = text[match.start(): match.start() + 1800]
            window_low = window.lower()
            if "fetch(" not in window_low:
                continue
            if any(
                token in window_low
                for token in (
                    "abortcontroller",
                    "signal:",
                    ".abort()",
                    "return () =>",
                    "ignore = true",
                    "cancelled = true",
                    "canceled = true",
                )
            ):
                continue

            line = text.count("\n", 0, match.start()) + 1
            findings.append(
                self.create_finding(
                    title="useEffect fetch lacks abort or cleanup handling",
                    context=f"{file_path}:{line}:useeffect-fetch",
                    file=file_path,
                    line_start=line,
                    description=(
                        "Detected a `fetch()` call inside `useEffect` without an obvious abort controller or "
                        "cleanup guard."
                    ),
                    why_it_matters=(
                        "Effects that keep running after unmount or dependency changes can race, update stale state, "
                        "and waste network work."
                    ),
                    suggested_fix=(
                        "Use `AbortController` with `signal`, or add a cleanup guard so the effect does not update "
                        "state after unmount or superseding requests."
                    ),
                    tags=["react", "useeffect", "fetch", "cleanup"],
                    confidence=0.84,
                    evidence_signals=["useeffect_fetch=true", "abort_cleanup_missing=true"],
                )
            )
            break
        return findings
