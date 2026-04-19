"""
Query Key Instability Rule

Flags React Query/SWR keys that embed inline objects/functions.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Category, Finding, FindingClassification, Severity
from rules.base import Rule


class QueryKeyInstabilityRule(Rule):
    id = "query-key-instability"
    name = "Unstable Query Key"
    description = "Detects inline objects/functions in query keys that break cache stability"
    category = Category.PERFORMANCE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _ALLOWLIST_PATH_MARKERS = (".test.", ".spec.", "__tests__", ".stories.")
    _PATTERNS = [
        (
            "react-query-object-literal",
            re.compile(r"queryKey\s*:\s*\[[^\]]*\{[^}]+\}[^\]]*\]", re.IGNORECASE | re.DOTALL),
        ),
        (
            "react-query-function-literal",
            re.compile(r"queryKey\s*:\s*\[[^\]]*(?:=>|function\s*\()", re.IGNORECASE | re.DOTALL),
        ),
        (
            "legacy-usequery-object-literal",
            re.compile(r"\buse(?:Infinite)?Query\s*\(\s*\[[^\]]*\{[^}]+\}[^\]]*\]", re.IGNORECASE | re.DOTALL),
        ),
        (
            "swr-object-literal",
            re.compile(r"\buseSWR(?:Infinite)?\s*\(\s*\[[^\]]*\{[^}]+\}[^\]]*\]", re.IGNORECASE | re.DOTALL),
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
        text_low = text.lower()
        if not any(token in text_low for token in ("usequery", "useswr", "querykey")):
            return []

        normalized_path = (file_path or "").lower().replace("\\", "/")
        if any(marker in normalized_path for marker in self._ALLOWLIST_PATH_MARKERS):
            return []

        max_findings_per_file = max(1, int(self.get_threshold("max_findings_per_file", 2)))
        findings: list[Finding] = []

        for pattern_name, pattern in self._PATTERNS:
            for match in pattern.finditer(text):
                if len(findings) >= max_findings_per_file:
                    break
                snippet = text[max(0, match.start() - 100) : min(len(text), match.end() + 100)]
                if self._inside_usememo(snippet):
                    continue
                line_number = text.count("\n", 0, match.start()) + 1
                findings.append(
                    self.create_finding(
                        title="Query key appears unstable",
                        context=pattern_name,
                        file=file_path,
                        line_start=line_number,
                        description=(
                            "Detected inline object/function in a query key. "
                            "This can produce a new key identity on each render."
                        ),
                        why_it_matters=(
                            "Unstable query keys reduce cache hit rate and can trigger unnecessary refetches."
                        ),
                        suggested_fix=(
                            "Build query keys from primitives or stable memoized values. "
                            "For object params, derive a stable key object with `useMemo` or normalize to primitives."
                        ),
                        confidence=0.88,
                        tags=["react", "react-query", "swr", "cache", "performance"],
                        evidence_signals=[f"pattern={pattern_name}"],
                        metadata={"decision_profile": {"pattern": pattern_name}},
                    )
                )
            if len(findings) >= max_findings_per_file:
                break

        return findings

    def _inside_usememo(self, snippet: str) -> bool:
        low = (snippet or "").lower()
        return "usememo(" in low and "querykey" in low
