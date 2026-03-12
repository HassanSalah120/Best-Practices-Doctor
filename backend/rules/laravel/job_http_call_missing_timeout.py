"""
Job HTTP Call Missing Timeout Rule

Detects queued jobs making outbound HTTP calls without an explicit timeout signal.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class JobHttpCallMissingTimeoutRule(Rule):
    id = "job-http-call-missing-timeout"
    name = "Job HTTP Call Missing Timeout"
    description = "Detects queued jobs with outbound HTTP calls and no timeout controls"
    category = Category.SECURITY
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]
    regex_file_extensions = [".php"]

    _HTTP_HINTS = ("http::", "guzzlehttp\\client", "new client(", "client->request(", "client->post(")
    _TIMEOUT_HINTS = ("http::timeout(", "->timeout(", "'timeout' =>", "\"timeout\" =>", "$timeout", "retryuntil(", "failontimeout")

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
        if "/jobs/" not in f"/{norm}":
            return []

        text = content or ""
        low = text.lower()
        if "shouldqueue" not in low:
            return []
        if not any(token in low for token in self._HTTP_HINTS):
            return []
        if any(token in low for token in self._TIMEOUT_HINTS):
            return []

        handle_match = re.search(r"function\s+handle\s*\(", text, re.IGNORECASE)
        line = text.count("\n", 0, handle_match.start()) + 1 if handle_match else 1
        return [
            self.create_finding(
                title="Queued job makes outbound HTTP calls without timeout controls",
                context=f"file:{file_path}",
                file=file_path,
                line_start=line,
                description=(
                    "Detected a queued job making outbound HTTP calls without an explicit request or job timeout."
                ),
                why_it_matters=(
                    "Jobs that wait indefinitely on remote services can block workers, increase retry storms, "
                    "and make failure handling unpredictable."
                ),
                suggested_fix=(
                    "Set explicit HTTP client timeouts such as `Http::timeout(...)` and, where appropriate, define "
                    "job-level timeout or failure behavior (`$timeout`, `$failOnTimeout`, `retryUntil()`)."
                ),
                tags=["laravel", "queues", "jobs", "http", "timeout"],
                confidence=0.81,
                evidence_signals=["job_http_call=true", "timeout_missing=true"],
            )
        ]
