"""
CSRF Exception Wildcard Risk Rule

Detects broad CSRF exception patterns like `*` or `webhooks/*`.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class CsrfExceptionWildcardRiskRule(Rule):
    id = "csrf-exception-wildcard-risk"
    name = "Broad CSRF Exception Wildcard"
    description = "Detects wildcard CSRF exception entries that can disable CSRF protection too broadly"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".php"]

    _TARGET_CALL = re.compile(r"validateCsrfTokens\s*\(", re.IGNORECASE)
    _WILDCARD_EXCEPT = re.compile(
        r"except\s*:\s*\[[^\]]*(['\"]\*['\"]|['\"][^'\"]*/\*['\"])",
        re.IGNORECASE | re.DOTALL,
    )
    _SAFE_HINTS = ("exact webhook", "exact path", "intentional narrow")
    severity_weight = 0
    confidence = 'high'
    fix_suggestion = 'Remove the broad csrf exception wildcard risk and enforce the relevant Laravel/React security control at the boundary. Add a regression test that proves unsafe input or configuration is rejected.'
    examples = {}
    priority = 1
    group = 'Access Control'
    applies_to = ['middleware']
    references = ['OWASP A01:2021 - Broken Access Control', 'CWE-352']
    related_rules = []
    false_positive_notes = ''
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'laravel', 'type': 'security', 'concern': 'csrf-exception-wildcard'}

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
        low_path = str(file_path or "").replace("\\", "/").lower()
        if not low_path.endswith(".php"):
            return []
        if "csrf" not in low_path and "validatecsrftokens" not in text.lower():
            return []
        if not self._TARGET_CALL.search(text):
            return []
        if any(hint in text.lower() for hint in self._SAFE_HINTS):
            return []

        match = self._WILDCARD_EXCEPT.search(text)
        if not match:
            return []

        line = text.count("\n", 0, match.start()) + 1
        confidence = 0.9
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        if confidence + 1e-9 < min_confidence:
            return []

        return [
            self.create_finding(
                title="CSRF exception uses wildcard path",
                context=f"{file_path}:{line}:csrf-except",
                file=file_path,
                line_start=line,
                description="Detected wildcard CSRF exception pattern that can disable CSRF checks for broad routes.",
                why_it_matters="Over-broad CSRF exceptions can expose authenticated browser flows to cross-site request forgery.",
                suggested_fix=(
                    "Replace wildcard CSRF exceptions with explicit, narrow endpoints only "
                    "(for example exact webhook callback paths)."
                ),
                confidence=confidence,
                tags=["laravel", "security", "csrf"],
                evidence_signals=["csrf_except_wildcard=true"],
            )
        ]

