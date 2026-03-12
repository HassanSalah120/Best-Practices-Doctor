"""
Insecure Session Cookie Config Rule

Detects Laravel session settings that weaken cookie protections.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class InsecureSessionCookieConfigRule(Rule):
    id = "insecure-session-cookie-config"
    name = "Insecure Session Cookie Config"
    description = "Detects Laravel session cookie settings with weak security defaults"
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

    _HTTP_ONLY_FALSE = re.compile(r"['\"]http_only['\"]\s*=>\s*(false|0|null)", re.IGNORECASE)
    _SECURE_FALSE = re.compile(r"['\"]secure['\"]\s*=>\s*false\b", re.IGNORECASE)
    _SECURE_DEFAULT_FALSE = re.compile(
        r"['\"]secure['\"]\s*=>\s*env\s*\(\s*['\"][^'\"]+['\"]\s*,\s*false\s*\)",
        re.IGNORECASE,
    )
    _SAME_SITE_WEAK = re.compile(r"['\"]same_site['\"]\s*=>\s*(null|['\"]none['\"]|false\b)", re.IGNORECASE)

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
        if norm != "config/session.php":
            return []

        text = content or ""
        issues: list[tuple[str, re.Match[str]]] = []

        for label, pattern in (
            ("`http_only` is disabled", self._HTTP_ONLY_FALSE),
            ("`secure` is explicitly false", self._SECURE_FALSE),
            ("`secure` defaults to false via `env(..., false)`", self._SECURE_DEFAULT_FALSE),
            ("`same_site` is weak (`null` or `none`)", self._SAME_SITE_WEAK),
        ):
            match = pattern.search(text)
            if match:
                issues.append((label, match))

        if not issues:
            return []

        first = min(match.start() for _, match in issues)
        line = text.count("\n", 0, first) + 1
        issue_text = "; ".join(label for label, _ in issues)

        return [
            self.create_finding(
                title="Session cookie configuration weakens browser protections",
                context="config/session.php",
                file=file_path,
                line_start=line,
                description=(
                    "Detected session cookie settings that reduce browser-enforced protections: "
                    f"{issue_text}."
                ),
                why_it_matters=(
                    "Weak session cookie settings make session theft, cross-site leakage, and downgrade "
                    "mistakes more likely in production."
                ),
                suggested_fix=(
                    "Prefer `http_only => true`, set `secure` so production cookies are HTTPS-only, and use "
                    "a restrictive `same_site` value such as `lax` or `strict` unless cross-site behavior is "
                    "explicitly required."
                ),
                tags=["laravel", "security", "session", "cookies"],
                confidence=0.91,
                evidence_signals=["session_cookie_hardening_missing=true", f"issues={len(issues)}"],
            )
        ]
