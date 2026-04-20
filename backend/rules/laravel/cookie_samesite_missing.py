"""
Cookie SameSite policy rule.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class CookieSameSiteMissingRule(Rule):
    id = "cookie-samesite-missing"
    name = "Cookie SameSite Missing"
    description = "Detects weak or missing SameSite configuration in session cookies"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".php"]

    _SAMESITE_ASSIGNMENT = re.compile(r"['\"]same_site['\"]\s*=>\s*(?P<value>[^\n]+)", re.IGNORECASE)
    _SAFE_VALUE = re.compile(r"['\"](lax|strict)['\"]", re.IGNORECASE)
    _NULL_VALUE = re.compile(r"\b(null|none)\b|['\"]none['\"]", re.IGNORECASE)

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
        if not norm.endswith("config/session.php"):
            return []

        match = self._SAMESITE_ASSIGNMENT.search(content or "")
        if match:
            value = str(match.groupdict().get("value") or "").strip()
            if self._SAFE_VALUE.search(value):
                return []
            if "env(" in value.lower():
                # Allow env() only if fallback is lax/strict.
                if self._SAFE_VALUE.search(value):
                    return []
            line = (content or "").count("\n", 0, match.start()) + 1
            reason = "null/none" if self._NULL_VALUE.search(value) else "non-recommended policy"
            return [
                self.create_finding(
                    title="Session cookie SameSite policy is weak or missing",
                    context=f"same_site => {value}",
                    file=file_path,
                    line_start=line,
                    description=f"Detected session `same_site` configuration with {reason}.",
                    why_it_matters="Weak SameSite settings increase CSRF and cross-site cookie leakage risk.",
                    suggested_fix="Set `same_site` to `'lax'` or `'strict'` in `config/session.php`.",
                    confidence=0.9 if reason == "null/none" else 0.82,
                    tags=["laravel", "security", "cookies", "samesite"],
                    evidence_signals=["session_same_site_weak=true"],
                )
            ]

        return [
            self.create_finding(
                title="Session cookie SameSite policy is not explicitly configured",
                context="same_site key missing",
                file=file_path,
                line_start=1,
                description="Could not find an explicit `same_site` setting in `config/session.php`.",
                why_it_matters="Missing SameSite configuration can leave cookie behavior inconsistent across environments.",
                suggested_fix="Add `'same_site' => 'lax'` (or `'strict'`) in `config/session.php`.",
                confidence=0.78,
                tags=["laravel", "security", "cookies", "samesite"],
                evidence_signals=["session_same_site_missing=true"],
            )
        ]
