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
    _RETRY_GUARDS = (
        "$tries",
        "function tries(",
        "backoff(",
        "retryuntil(",
        "$backoff",
        "$maxexceptions",
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

        text = content or ""
        low = text.lower()
        if "shouldqueue" not in low:
            return []
        if not any(token in low for token in self._SIDE_EFFECTS):
            return []
        if any(token in low for token in self._RETRY_GUARDS):
            return []

        handle_match = re.search(r"function\s+handle\s*\(", text, re.IGNORECASE)
        line = text.count("\n", 0, handle_match.start()) + 1 if handle_match else 1
        return [
            self.create_finding(
                title="Queued job has side effects but no explicit retry policy",
                context=f"file:{file_path}",
                file=file_path,
                line_start=line,
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
                confidence=0.77,
                evidence_signals=["side_effect_job=true", "retry_policy_missing=true"],
            )
        ]
