"""
Job Missing Idempotency Guard Rule

Detects queued Laravel jobs with visible side effects but no obvious deduplication or idempotency signal.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class JobMissingIdempotencyGuardRule(Rule):
    id = "job-missing-idempotency-guard"
    name = "Job Missing Idempotency Guard"
    description = "Detects queued jobs with side effects and no obvious idempotency guard"
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
        "storage::",
        "dispatch(",
        "event(",
        "db::",
        "->save(",
        "->update(",
        "->delete(",
        "::create(",
        "insert(",
    )
    _GUARDS = (
        "shouldbeunique",
        "withoutoverlapping",
        "cache::lock",
        "uniqueid(",
        "updateorcreate(",
        "firstorcreate(",
        "upsert(",
        "lockforupdate(",
        "idempot",
        "deduplicat",
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
        if "function handle" not in low:
            return []
        if "shouldqueue" not in low:
            return []
        if not any(token in low for token in self._SIDE_EFFECTS):
            return []
        if any(token in low for token in self._GUARDS):
            return []

        handle_match = re.search(r"function\s+handle\s*\(", text, re.IGNORECASE)
        line = text.count("\n", 0, handle_match.start()) + 1 if handle_match else 1

        return [
            self.create_finding(
                title="Queued job shows side effects without an idempotency guard",
                context=f"file:{file_path}",
                file=file_path,
                line_start=line,
                description=(
                    "Detected a queued job with visible side-effect operations but no clear uniqueness, "
                    "locking, or idempotent write signal."
                ),
                why_it_matters=(
                    "Retried or duplicate jobs can send duplicate notifications, create inconsistent state, "
                    "or replay external side effects."
                ),
                suggested_fix=(
                    "Consider `ShouldBeUnique`, `WithoutOverlapping`, cache or database locking, or idempotent "
                    "write patterns such as `updateOrCreate` or `upsert` for jobs that can be retried or enqueued twice."
                ),
                tags=["laravel", "security", "queues", "jobs", "idempotency"],
                confidence=0.78,
                evidence_signals=["queued_job_side_effects=true", "idempotency_guard_missing=true"],
            )
        ]
