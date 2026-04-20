"""
Missing HSTS header rule.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class MissingHstsHeaderRule(Rule):
    id = "missing-hsts-header"
    name = "Missing HSTS Header"
    description = "Detects missing Strict-Transport-Security hardening in middleware/header configuration"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".php"]

    _HSTS_SIGNAL = re.compile(r"(strict-transport-security|hsts)", re.IGNORECASE)
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
        if self._HSTS_SIGNAL.search(content or ""):
            return []
        if "middleware" not in (content or "").lower() and "headers" not in (content or "").lower():
            return []

        return [
            self.create_finding(
                title="HSTS header hardening appears missing",
                context="Strict-Transport-Security not configured",
                file=file_path,
                line_start=1,
                description=(
                    "Could not find `Strict-Transport-Security` header handling in middleware/kernel bootstrapping."
                ),
                why_it_matters=(
                    "Without HSTS, browsers may downgrade to insecure HTTP, enabling man-in-the-middle attacks."
                ),
                suggested_fix=(
                    "Add a security headers middleware that sets `Strict-Transport-Security` for HTTPS responses."
                ),
                confidence=0.82,
                tags=["laravel", "security", "headers", "hsts"],
                evidence_signals=["hsts_header_missing=true"],
            )
        ]
