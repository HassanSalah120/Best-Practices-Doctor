"""
Job Missing Retry Policy Rule

Detects queued jobs with side effects but no explicit retry or backoff policy.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class JobMissingRetryPolicyRule(Rule):
    id = "job-missing-retry-policy"
    name = "Job Missing Retry Policy"
    description = "Detects side-effecting queued jobs without explicit retry or backoff controls"
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

    _SIDE_EFFECTS = (
        "mail::",
        "notification::",
        "http::",
        "dispatch(",
        "event(",
        "->save(",
        "->update(",
        "->delete(",
        "::create(",
        "insert(",
    )
    _DB_ONLY_SIDE_EFFECTS = (
        "->save(",
        "->update(",
        "->delete(",
        "::create(",
        "insert(",
    )
    _RETRY_GUARDS = (
        "$tries",
        "function tries(",
        "backoff(",
        "retryuntil(",
        "$backoff",
        "$maxexceptions",
        "throttlesexceptions",
        "retryuntil",
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
        side_effect_hits = [token for token in self._SIDE_EFFECTS if token in body_low]
        if not side_effect_hits:
            return []
        if bool(self.get_threshold("ignore_db_only_jobs", True)):
            if side_effect_hits and all(token in self._DB_ONLY_SIDE_EFFECTS for token in side_effect_hits):
                return []
        if any(token in low for token in self._RETRY_GUARDS):
            return []

        confidence = 0.7 + (0.03 * min(len(side_effect_hits), 3))
        if "http::" in side_effect_hits:
            confidence += 0.05
        confidence = min(0.95, confidence)
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        if confidence + 1e-9 < min_confidence:
            return []

        return [
            self.create_finding(
                title="Queued job has side effects but no explicit retry policy",
                context=f"file:{file_path}",
                file=file_path,
                line_start=handle_line,
                description=(
                    "Detected a queued job with side effects but no visible retry, backoff, or retry-until policy."
                ),
                why_it_matters=(
                    "Default retry behavior can be too aggressive for external APIs, billing, and notifications, "
                    "causing duplicate or bursty failures."
                ),
                suggested_fix=(
                    "Define `tries`, `backoff()`, `retryUntil()`, or related failure controls so job retries match "
                    "the safety requirements of the side effect."
                ),
                tags=["laravel", "queues", "jobs", "retry"],
                confidence=confidence,
                evidence_signals=[
                    "side_effect_job=true",
                    "retry_policy_missing=true",
                    f"side_effect_count={len(side_effect_hits)}",
                ],
            )
        ]

    def _queue_or_integration_capability_enabled(self, facts: Facts) -> bool:
        caps = getattr(getattr(facts, "project_context", None), "backend_capabilities", {}) or {}
        required = ("queue_heavy", "external_integrations_heavy", "billing", "notifications_heavy", "realtime")
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
