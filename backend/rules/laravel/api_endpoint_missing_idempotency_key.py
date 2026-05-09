"""API Endpoint Missing Idempotency Key Rule."""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class ApiEndpointMissingIdempotencyKeyRule(Rule):
    id = "api-endpoint-missing-idempotency-key"
    name = "API Endpoint Missing Idempotency Key"
    description = "Detects mutating API handlers that create durable state without an idempotency key guard"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".php"]
    severity_weight = 8
    confidence = "high"
    fix_suggestion = (
        "Require an Idempotency-Key header for externally retried mutating endpoints and store the processed key "
        "with a bounded TTL or durable unique constraint."
    )
    examples = {
        "bad": "public function store(Request $request) { return Order::create($request->validated()); }",
        "good": "public function store(Request $request) { $key = $request->header('Idempotency-Key'); return Idempotency::run($key, fn() => Order::create(...)); }",
    }
    priority = 1
    group = "API Design"
    applies_to = ["controller", "route"]
    references = ["Stripe API idempotent requests", "AWS Builders Library - retries and idempotency"]
    related_rules = ["job-missing-idempotency-guard", "webhook-replay-protection-missing"]
    false_positive_notes = (
        "May be a false positive when idempotency is enforced by middleware, an API gateway, or a shared action "
        "outside the scanned handler."
    )
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "security", "concern": "api-idempotency"}

    _MUTATING_HANDLER = re.compile(r"function\s+(store|create|update|charge|checkout|pay|subscribe)\s*\(", re.IGNORECASE)
    _WRITE_SIGNAL = re.compile(
        r"(::create\s*\(|->create\s*\(|->save\s*\(|->update\s*\(|DB::transaction\s*\(|dispatch\s*\(|Http::(?:post|put|patch|send)\s*\()",
        re.IGNORECASE,
    )
    _IDEMPOTENCY_SIGNAL = re.compile(
        r"(idempotenc|Idempotency-Key|idempotency-key|IdempotencyKey|Cache::add\s*\(|firstOrCreate\s*\(|updateOrCreate\s*\(|upsert\s*\(|unique\s*\(|lockForUpdate\s*\()",
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
        if "/controllers/" not in f"/{normalized}" and "/actions/" not in f"/{normalized}":
            return []
        text = content or ""
        if self._IDEMPOTENCY_SIGNAL.search(text):
            return []

        findings: list[Finding] = []
        for match in self._MUTATING_HANDLER.finditer(text):
            body, line = self._extract_method_body(text, match.start())
            if not body or not self._WRITE_SIGNAL.search(body):
                continue
            findings.append(
                self.create_finding(
                    title="Mutating API endpoint lacks idempotency key handling",
                    file=file_path,
                    line_start=line,
                    context=f"{file_path}:{line}",
                    description="This mutating endpoint writes durable state but no idempotency-key guard was detected.",
                    why_it_matters=(
                        "Network retries, client double-submits, and payment/provider retries can replay the same request "
                        "and silently duplicate records or side effects."
                    ),
                    suggested_fix=self.fix_suggestion,
                    confidence=0.86,
                    tags=["laravel", "api", "idempotency", "distributed-systems"],
                    evidence_signals=["mutating_endpoint=true", "durable_write=true", "idempotency_guard_missing=true"],
                )
            )
        return findings

    def _extract_method_body(self, text: str, offset: int) -> tuple[str, int]:
        open_at = text.find("{", offset)
        if open_at < 0:
            return "", text.count("\n", 0, offset) + 1
        depth = 1
        i = open_at + 1
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    return text[open_at + 1 : i], text.count("\n", 0, offset) + 1
            i += 1
        return text[open_at + 1 :], text.count("\n", 0, offset) + 1
