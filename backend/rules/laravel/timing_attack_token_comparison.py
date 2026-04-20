"""
Timing attack token comparison rule.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class TimingAttackTokenComparisonRule(Rule):
    id = "timing-attack-token-comparison"
    name = "Timing Attack Token Comparison"
    description = "Detects direct token/hash equality comparisons that should use constant-time `hash_equals`"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".php"]

    _SENSITIVE_VAR = r"[A-Za-z_][A-Za-z0-9_]*(token|hash|secret|signature|hmac)[A-Za-z0-9_]*"
    _COMPARE = re.compile(
        rf"(?P<a>\${_SENSITIVE_VAR}|\${_SENSITIVE_VAR})\s*(===|==)\s*(?P<b>\$[A-Za-z_][A-Za-z0-9_]*)"
        rf"|(?P<c>\$[A-Za-z_][A-Za-z0-9_]*)\s*(===|==)\s*(?P<d>\${_SENSITIVE_VAR})",
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
        norm = (file_path or "").replace("\\", "/").lower()
        if norm.startswith("tests/") or norm.startswith("test/") or "/tests/" in norm or "/test/" in norm:
            return []

        findings: list[Finding] = []
        for i, line in enumerate((content or "").splitlines(), start=1):
            low = line.lower()
            if "hash_equals" in low:
                continue
            if self._COMPARE.search(line):
                findings.append(
                    self.create_finding(
                        title="Sensitive token compared using non-constant-time equality",
                        context=line.strip()[:90],
                        file=file_path,
                        line_start=i,
                        description=(
                            "Detected `==`/`===` comparison involving token/hash/secret values. "
                            "Use `hash_equals()` for constant-time comparison."
                        ),
                        why_it_matters="Direct string comparisons can leak timing side channels for secret values.",
                        suggested_fix="Replace direct equality checks with `hash_equals($expected, $actual)`.",
                        confidence=0.9,
                        tags=["laravel", "security", "timing-attack", "hash_equals"],
                        evidence_signals=["sensitive_equality_operator=true"],
                    )
                )
        return findings
