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
    _DB_ONLY_SIDE_EFFECTS = (
        "db::",
        "->save(",
        "->update(",
        "->delete(",
        "::create(",
        "insert(",
    )
    _GUARDS = (
        "shouldbeunique",
        "shouldbeuniqueuntilprocessing",
        "withoutoverlapping",
        "cache::lock",
        "uniqueid(",
        "updateorcreate(",
        "firstorcreate(",
        "insertorignore(",
        "firstornew(",
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
        require_queue_capability = bool(self.get_threshold("require_queue_capability", False))
        if require_queue_capability and not self._queue_or_integration_capability_enabled(facts):
            return []

        text = content or ""
        low = text.lower()
        handle_body, handle_line = self._extract_handle_body(text)
        if not handle_body:
            return []
        if "shouldqueue" not in low:
            return []
        body_low = handle_body.lower()
        side_effect_hits = [token for token in self._SIDE_EFFECTS if token in body_low]
        if not side_effect_hits:
            return []
        if any(token in low for token in self._GUARDS):
            return []
        if bool(self.get_threshold("ignore_db_only_jobs", True)):
            if side_effect_hits and all(token in self._DB_ONLY_SIDE_EFFECTS for token in side_effect_hits):
                return []

        confidence = 0.72 + (0.03 * min(len(side_effect_hits), 3))
        if any(token in side_effect_hits for token in ("http::", "mail::", "notification::")):
            confidence += 0.04
        confidence = min(0.95, confidence)
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        if confidence + 1e-9 < min_confidence:
            return []

        return [
            self.create_finding(
                title="Queued job shows side effects without an idempotency guard",
                context=f"file:{file_path}",
                file=file_path,
                line_start=handle_line,
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
                confidence=confidence,
                evidence_signals=[
                    "queued_job_side_effects=true",
                    "idempotency_guard_missing=true",
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
