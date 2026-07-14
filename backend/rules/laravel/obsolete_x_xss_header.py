"""
Obsolete X-XSS-Protection Header Rule

Flags presence of the `X-XSS-Protection` header in middleware or kernel
configuration. This header is obsolete — modern browsers ignore it and it
provides no security value while acting as a fingerprinting vector.
"""

from __future__ import annotations

import re
from pathlib import Path

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class ObsoleteXXssHeaderRule(Rule):
    id = "obsolete-x-xss-protection-header"
    name = "Obsolete X-XSS-Protection Header"
    description = "Detects obsolete X-XSS-Protection header in middleware/kernel configuration"
    category = Category.SECURITY
    default_severity = Severity.LOW
    type = "regex"
    regex_file_extensions = [".php"]
    severity_weight = 2
    confidence = "high"
    fix_suggestion = (
        "Remove the `X-XSS-Protection` header. Modern browsers ignore it, and it provides "
        "no security value while acting as a fingerprinting vector. "
        "Use `Content-Security-Policy` (CSP) and `X-Content-Type-Options: nosniff` instead."
    )
    examples = {
        "bad": "header('X-XSS-Protection: 1; mode=block');",
        "good": "// Remove X-XSS-Protection entirely",
    }
    priority = 3
    group = "Security Hardening"
    applies_to = ["config", "middleware"]
    references = [
        "OWASP: X-XSS-Protection is deprecated",
        "MDN: X-XSS-Protection is obsolete",
    ]
    related_rules = ["missing-content-security-policy", "security-headers-baseline-missing"]
    false_positive_notes = (
        "Some legacy proxies or CDN configurations still send this header. "
        "Only flag code-level definitions, not infrastructure headers."
    )
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = True
    tags = {"domain": "laravel", "type": "security", "concern": "obsolete-header"}

    _XSS_HEADER = re.compile(r"X-XSS-Protection", re.IGNORECASE)
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

        if not self._XSS_HEADER.search(content):
            return []

        line = 1
        for i, line_content in enumerate(content.split("\n"), 1):
            if self._XSS_HEADER.search(line_content):
                line = i
                break

        return [
            self.create_finding(
                title="Obsolete X-XSS-Protection header detected",
                context="X-XSS-Protection header present in middleware/kernel",
                file=file_path,
                line_start=line,
                description=(
                    "The `X-XSS-Protection` header is present in middleware or kernel configuration. "
                    "This header is obsolete — modern browsers ignore it. It provides no security value "
                    "and can be used for browser fingerprinting."
                ),
                why_it_matters=(
                    "Keeping obsolete headers adds maintenance burden, creates a false sense of security, "
                    "and can be used as a fingerprinting signal. Remove it and rely on CSP instead."
                ),
                suggested_fix=self.fix_suggestion,
                confidence=0.9,
                tags=["laravel", "security", "headers", "obsolete"],
                evidence_signals=[
                    "obsolete_header_found=x-xss-protection",
                    "scan_scope=project_security_headers",
                ],
            ),
        ]
