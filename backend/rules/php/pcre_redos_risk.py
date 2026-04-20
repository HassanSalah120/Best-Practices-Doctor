"""
PCRE ReDoS risk rule.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class PcreRedosRiskRule(Rule):
    id = "pcre-redos-risk"
    name = "PCRE ReDoS Risk"
    description = "Detects nested quantifier regex patterns in preg_match/preg_replace usage"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".php"]

    _PREG_CALL = re.compile(r"\bpreg_(match|replace)\s*\(\s*(?P<pattern>['\"/].+?)\s*,", re.IGNORECASE)
    _NESTED_QUANT = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*]")
    _ALT_NESTED = re.compile(r"\((?:[^()\\]|\\.)*\|(?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*]")

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
        norm = (file_path or "").replace("\\", "/").lower()
        if (
            norm.startswith("tests/")
            or norm.startswith("test/")
            or "/tests/" in norm
            or "/test/" in norm
            or "/migrations/" in norm
        ):
            return []

        findings: list[Finding] = []
        for i, line in enumerate((content or "").splitlines(), start=1):
            call = self._PREG_CALL.search(line)
            if not call:
                continue
            pattern = str(call.groupdict().get("pattern") or "")
            if not pattern:
                continue
            if not (self._NESTED_QUANT.search(pattern) or self._ALT_NESTED.search(pattern)):
                continue
            findings.append(
                self.create_finding(
                    title="Regex pattern may be vulnerable to catastrophic backtracking (ReDoS)",
                    context=line.strip()[:100],
                    file=file_path,
                    line_start=i,
                    description=(
                        "Detected nested quantifier regex in `preg_*` call, which can trigger catastrophic backtracking."
                    ),
                    why_it_matters="ReDoS can cause CPU spikes and request-time denial of service on crafted input.",
                    suggested_fix="Refactor regex to avoid nested quantifiers or use bounded/atomic groups.",
                    confidence=0.88,
                    tags=["php", "security", "regex", "redos"],
                    evidence_signals=["nested_quantifier_pattern=true"],
                )
            )
        return findings
