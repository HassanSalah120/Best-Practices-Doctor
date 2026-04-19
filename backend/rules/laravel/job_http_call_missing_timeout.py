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

    _HTTP_HINTS = ("http::", "guzzlehttp\\client", "new client(", "client->request(", "client->post(", "curl_setopt(")
    _TIMEOUT_HINTS = (
        "http::timeout(",
        "->timeout(",
        "'timeout' =>",
        "\"timeout\" =>",
        "$timeout",
        "retryuntil(",
        "failontimeout",
        "$failontimeout",
    )
    _WRAPPER_TIMEOUT_HINTS = (
        "withtimeout(",
        "settimeout(",
        "defaulttimeout",
        "timeoutseconds",
        "requesttimeout",
        "httptimeout",
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
        if "/jobs/" not in f"/{norm}":
            return []
        require_queue_capability = bool(self.get_threshold("require_queue_capability", False))
        if require_queue_capability and not self._queue_or_integration_capability_enabled(facts):
            return []

        text = content or ""
        low = text.lower()
        if "shouldqueue" not in low:
            return []
        handle_body, handle_line = self._extract_handle_body(text)
        if not handle_body:
            return []
        body_low = handle_body.lower()
        if not any(token in body_low for token in self._HTTP_HINTS):
            return []
        if any(token in body_low for token in self._TIMEOUT_HINTS):
            return []
        if any(token in low for token in self._WRAPPER_TIMEOUT_HINTS):
            return []

        confidence = 0.81
        if "guzzlehttp\\client" in body_low or "client->request(" in body_low:
            confidence = 0.78
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        if confidence + 1e-9 < min_confidence:
            return []
        return [
            self.create_finding(
                title="Queued job makes outbound HTTP calls without timeout controls",
                context=f"file:{file_path}",
                file=file_path,
                line_start=handle_line,
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
                confidence=confidence,
                evidence_signals=["job_http_call=true", "timeout_missing=true", "wrapper_timeout_hint_missing=true"],
            )
        ]

    def _queue_or_integration_capability_enabled(self, facts: Facts) -> bool:
        caps = getattr(getattr(facts, "project_context", None), "backend_capabilities", {}) or {}
        required = ("queue_heavy", "external_integrations_heavy", "billing", "realtime")
        for key in required:
            payload = caps.get(key)
            if isinstance(payload, dict) and bool(payload.get("enabled", False)):
                return True
        return False

    def _extract_handle_body(self, text: str) -> tuple[str, int]:
        match = re.search(r"function\s+handle\s*\([^)]*\)\s*(?::\s*[^{]+)?\{", text, re.IGNORECASE)
        if not match:
            return "", 1
        start = match.end()
        line = text.count("\n", 0, match.start()) + 1
        depth = 1
        i = start
        while i < len(text):
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start:i], line
            i += 1
        return text[start:], line
