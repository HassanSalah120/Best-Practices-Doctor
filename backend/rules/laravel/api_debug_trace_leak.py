"""
API Debug Trace Leak detector.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class ApiDebugTraceLeakRule(Rule):
    id = "api-debug-trace-leak"
    name = "API Debug Trace Leak"
    description = "Detects production debug defaults that can leak stack traces or internals"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".env", ".env.example", ".php"]

    _ALLOWLIST = ("/tests/", "/test/", "/vendor/")
    _DEBUG_TRUE = re.compile(r"APP_DEBUG\s*=\s*(true|1)\b", re.IGNORECASE)
    _DEBUG_DEFAULT_TRUE = re.compile(
        r"['\"]debug['\"]\s*=>\s*env\s*\(\s*['\"]APP_DEBUG['\"]\s*,\s*true\s*\)",
        re.IGNORECASE,
    )
    _DEBUG_EXPLICIT_FALSE = re.compile(r"APP_DEBUG\s*=\s*false\b", re.IGNORECASE)

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
        if any(marker in norm for marker in self._ALLOWLIST):
            return []
        if not (
            norm.endswith(".env")
            or norm.endswith(".env.example")
            or norm.endswith("config/app.php")
            or norm.endswith("/config/app.php")
        ):
            return []

        findings: list[Finding] = []
        lines = content.splitlines()

        for i, line in enumerate(lines, start=1):
            if self._DEBUG_TRUE.search(line):
                findings.append(
                    self.create_finding(
                        title="APP_DEBUG appears enabled in production-facing config",
                        context=line.strip()[:80],
                        file=file_path,
                        line_start=i,
                        description=(
                            "Detected `APP_DEBUG=true` style configuration, which can expose stack traces and internal details."
                        ),
                        why_it_matters=(
                            "Verbose framework traces can leak secrets, SQL, file paths, and implementation details to attackers."
                        ),
                        suggested_fix=(
                            "Set `APP_DEBUG=false` for production and keep it enabled only in local development environments."
                        ),
                        confidence=0.92,
                        tags=["laravel", "security", "debug", "trace-leak"],
                        evidence_signals=["app_debug_enabled=true"],
                    )
                )
            elif self._DEBUG_DEFAULT_TRUE.search(line):
                findings.append(
                    self.create_finding(
                        title="Debug config defaults to true",
                        context=line.strip()[:80],
                        file=file_path,
                        line_start=i,
                        description=(
                            "Detected `config('app.debug')` fallback defaulting to `true`, which is unsafe for production."
                        ),
                        why_it_matters=(
                            "Unsafe defaults increase the chance of production trace leaks after deployment drift or env misconfiguration."
                        ),
                        suggested_fix=(
                            "Use `env('APP_DEBUG', false)` and enforce production config with `APP_DEBUG=false`."
                        ),
                        confidence=0.88,
                        tags=["laravel", "security", "debug", "trace-leak"],
                        evidence_signals=["app_debug_default=true"],
                    )
                )

        if findings:
            return findings

        # Explicit false is safe and should not fire.
        if self._DEBUG_EXPLICIT_FALSE.search(content):
            return []

        # For .env files missing explicit APP_DEBUG, emit a low-confidence warning.
        if norm.endswith(".env") and "app_debug" not in content.lower():
            return [
                self.create_finding(
                    title="APP_DEBUG not explicitly configured",
                    context="APP_DEBUG missing",
                    file=file_path,
                    line_start=1,
                    description="APP_DEBUG is not explicitly set; production-safe defaults may not be guaranteed.",
                    why_it_matters="Implicit defaults can cause accidental debug exposure during deployment drift.",
                    suggested_fix="Set `APP_DEBUG=false` explicitly in production environment files.",
                    confidence=0.74,
                    tags=["laravel", "security", "debug"],
                    evidence_signals=["app_debug_missing=true"],
                )
            ]
        return []
