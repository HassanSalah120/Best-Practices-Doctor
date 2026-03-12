"""
Unsafe CSP Policy Rule

Detects Content-Security-Policy definitions that still allow unsafe inline or eval execution.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class UnsafeCspPolicyRule(Rule):
    id = "unsafe-csp-policy"
    name = "Unsafe CSP Policy"
    description = "Detects CSP definitions that allow unsafe inline or eval sources"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]
    regex_file_extensions = [".php"]

    _HEADER_HINTS = ("content-security-policy", "script-src", "style-src", "csp")
    _UNSAFE = re.compile(r"'unsafe-(inline|eval)'|\"unsafe-(inline|eval)\"", re.IGNORECASE)

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
        low = text.lower()
        if not any(hint in low for hint in self._HEADER_HINTS):
            return []

        match = self._UNSAFE.search(text)
        if not match:
            return []

        line = text.count("\n", 0, match.start()) + 1
        token = match.group(0)

        return [
            self.create_finding(
                title="Content-Security-Policy includes unsafe source allowances",
                context=f"{file_path}:{line}:csp",
                file=file_path,
                line_start=line,
                description=(
                    f"Detected a CSP definition containing `{token}`, which weakens script or style execution "
                    "protections."
                ),
                why_it_matters=(
                    "Allowing `unsafe-inline` or `unsafe-eval` makes CSP far less effective against XSS and "
                    "script injection."
                ),
                suggested_fix=(
                    "Remove unsafe CSP allowances where possible. Prefer nonces, hashes, strict-dynamic, and "
                    "explicit source lists instead of inline or eval-based execution."
                ),
                tags=["laravel", "security", "csp", "xss"],
                confidence=0.9,
                evidence_signals=[f"unsafe_token={token}", "csp_policy_weak=true"],
            )
        ]
