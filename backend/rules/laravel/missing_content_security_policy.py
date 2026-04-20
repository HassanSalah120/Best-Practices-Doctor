"""
Missing Content Security Policy rule.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class MissingContentSecurityPolicyRule(Rule):
    id = "missing-content-security-policy"
    name = "Missing Content Security Policy"
    description = "Detects missing CSP middleware/header registration in Laravel bootstrap/kernel paths"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".php"]

    _CSP_SIGNAL = re.compile(
        r"(content-security-policy|contentsecuritypolicy|cspmiddleware|spatie\\csp)",
        re.IGNORECASE,
    )
    _TARGET_FILES = (
        "app/http/kernel.php",
        "bootstrap/app.php",
        "app/http/middleware",
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
        if not any(token in norm for token in self._TARGET_FILES):
            return []
        payload = content or ""
        if self._CSP_SIGNAL.search(payload):
            return []
        if "middleware" not in payload.lower() and "headers" not in payload.lower():
            return []
        return [
            self.create_finding(
                title="Content Security Policy appears missing",
                context="CSP middleware/header not found",
                file=file_path,
                line_start=1,
                description="Could not find CSP middleware registration or `Content-Security-Policy` header handling.",
                why_it_matters="CSP reduces XSS blast radius by constraining allowed script/style sources.",
                suggested_fix=(
                    "Register CSP middleware or set `Content-Security-Policy` response headers in your security middleware stack."
                ),
                confidence=0.8,
                tags=["laravel", "security", "headers", "csp"],
                evidence_signals=["csp_header_missing=true"],
            )
        ]
