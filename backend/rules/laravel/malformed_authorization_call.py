"""
Malformed Authorization Call Rule

Detects $this->authorize->method() patterns that indicate a property/method
collision — the developer wrote `$this->authorize` (accessing a property named
`authorize`) then chained `->authorize(...)` (calling a method on it), or
similar malformed authorization chains that silently bypass policy checks.
"""

from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class MalformedAuthorizationCallRule(Rule):
    id = "malformed-authorization-call"
    name = "Malformed Authorization Call"
    description = "Detects $this->authorize->method() patterns that silently bypass authorization"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".php"]
    severity_weight = 8
    confidence = "high"
    fix_suggestion = (
        "Replace `$this->authorize->authorize(...)` with `$this->authorize(...)`. "
        "The `->authorize` property access followed by a method call on it indicates "
        "a typo or naming collision that leaves the intended policy check unevaluated."
    )
    examples = {
        "bad": "$this->authorize->authorize($request->user(), $resource)",
        "good": "$this->authorize($request->user(), $resource)",
    }
    priority = 1
    group = "Access Control"
    applies_to = ["controller", "service"]
    references = ["CWE-863: Incorrect Authorization"]
    related_rules = ["authorization-bypass-risk", "policy-coverage-on-mutations"]
    false_positive_notes = (
        "Raises a finding when `$this->authorize` is used as a property access then "
        "chained with a method call. This pattern almost always indicates a bug."
    )
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "security", "concern": "authorization"}

    _BAD_AUTH_CHAIN = re.compile(
        r'\$this\s*->\s*authorize\s*->\s*\w+\s*\(',
        re.IGNORECASE,
    )
    _TARGET_PATHS = ("/controllers/", "/services/", "/repositories/", "/policies/")

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
        if not any(token in norm for token in self._TARGET_PATHS):
            return []
        if "/tests/" in norm:
            return []

        findings: list[Finding] = []
        for match in self._BAD_AUTH_CHAIN.finditer(content):
            line = content.count("\n", 0, match.start()) + 1
            findings.append(
                self.create_finding(
                    title="Authorization call appears malformed",
                    context=f"$this->authorize->{match.group(0).split('->')[-1].rstrip('(')}()",
                    file=file_path,
                    line_start=line,
                    description=(
                        "Detected `$this->authorize->method(...)` — this accesses `$this->authorize` "
                        "as a property (likely null or an unexpected object) and calls a method on it, "
                        "rather than calling `$this->authorize(...)` directly. "
                        "The intended authorization check is likely never evaluated."
                    ),
                    why_it_matters=(
                        "Malformed authorization calls silently bypass policy checks, "
                        "leaving sensitive routes unprotected. This is a high-risk defect."
                    ),
                    suggested_fix=self.fix_suggestion,
                    confidence=0.88,
                    tags=["laravel", "security", "authorization", "bug"],
                    evidence_signals=[
                        "malformed_authorization_chain=true",
                        f"match={match.group(0).strip()[:80]}",
                    ],
                ),
            )
        return findings
