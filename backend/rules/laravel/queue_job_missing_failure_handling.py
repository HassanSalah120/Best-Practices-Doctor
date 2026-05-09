"""Queue Job Missing Failure Handling Rule."""

from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class QueueJobMissingFailureHandlingRule(Rule):
    id = "queue-job-missing-failure-handling"
    name = "Queue Job Missing Failure Handling"
    description = "Detects queued jobs with side effects but no visible retry/backoff/failed handling"
    category = Category.SECURITY
    default_severity = Severity.MEDIUM
    type = "regex"
    regex_file_extensions = [".php"]
    severity_weight = 5
    confidence = "high"
    fix_suggestion = (
        "Define retry/backoff behavior and a failed(Throwable $e) handler for jobs that touch external systems "
        "or durable state."
    )
    examples = {
        "bad": "class SyncInvoice implements ShouldQueue { public function handle() { Http::post(...); } }",
        "good": "class SyncInvoice implements ShouldQueue { public $tries = 3; public function backoff(){ return [10, 60]; } public function failed(Throwable $e){ report($e); } }",
    }
    priority = 2
    group = "Queue & Jobs"
    applies_to = ["job"]
    references = ["Laravel Queues - Handling Failed Jobs"]
    related_rules = ["job-missing-idempotency-guard", "job-http-call-missing-timeout"]
    false_positive_notes = "May be a false positive when queue failure handling is centralized by middleware or worker policy."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "security", "concern": "queue-failure-handling"}

    _SIDE_EFFECTS = re.compile(
        r"(Http::|Mail::|Notification::|Storage::|dispatch\s*\(|event\s*\(|->save\s*\(|->update\s*\(|->delete\s*\(|::create\s*\()",
        re.IGNORECASE,
    )
    _HANDLING = re.compile(
        r"(function\s+failed\s*\(|public\s+\$tries\s*=|public\s+\$backoff\s*=|function\s+backoff\s*\(|function\s+retryUntil\s*\(|ThrottlesExceptions|WithoutOverlapping)",
        re.IGNORECASE,
    )

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        normalized = (file_path or "").replace("\\", "/").lower()
        if "/jobs/" not in f"/{normalized}":
            return []
        text = content or ""
        if "ShouldQueue" not in text or self._HANDLING.search(text):
            return []
        handle_body, line = self._extract_handle_body(text)
        if not handle_body or not self._SIDE_EFFECTS.search(handle_body):
            return []
        return [
            self.create_finding(
                title="Queued job has side effects without failure handling",
                file=file_path,
                line_start=line,
                context=f"{file_path}:{line}",
                description="This queued job performs side effects but no retry/backoff/failed handler was detected.",
                why_it_matters=(
                    "Worker crashes, provider outages, and poison messages can lose work or create retry storms unless "
                    "jobs define explicit failure behavior."
                ),
                suggested_fix=self.fix_suggestion,
                confidence=0.84,
                tags=["laravel", "queues", "resilience", "failure-handling"],
                evidence_signals=["should_queue=true", "side_effects=true", "failure_handling_missing=true"],
            ),
        ]

    def _extract_handle_body(self, text: str) -> tuple[str, int]:
        match = re.search(r"function\s+handle\s*\([^)]*\)\s*(?::\s*[^{]+)?\{", text, re.IGNORECASE)
        if not match:
            return "", 1
        start = match.end()
        line = text.count("\n", 0, match.start()) + 1
        depth = 1
        i = start
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    return text[start:i], line
            i += 1
        return text[start:], line
