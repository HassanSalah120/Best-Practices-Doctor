"""Missing health check endpoint rule."""
from __future__ import annotations

import re
from pathlib import Path

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class MissingHealthCheckEndpointRule(Rule):
    id = "missing-health-check-endpoint"
    name = "Missing Health Check Endpoint"
    description = "Detects Laravel apps without a health, status, or ping route"
    category = Category.ARCHITECTURE
    default_severity = Severity.MEDIUM
    type = "ast"
    severity_weight = 5
    confidence = "medium"
    fix_suggestion = "Add a GET /health endpoint that returns 200 OK. Required for load balancers, Docker health checks, and uptime monitors."
    examples = {"good": "Route::get('/health', fn() => response()->json(['status' => 'ok']));"}
    priority = 3
    group = "Architecture Integrity"
    applies_to = ["route"]
    references = []
    related_rules = []
    false_positive_notes = "Projects using a dedicated health package may expose routes dynamically; those should be verified manually if static routes are absent."
    detection_type = "regex"
    analysis_cost = "medium"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "architecture", "concern": "health-check"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if any("spatie/laravel-health" in p.lower() for p in facts.files):
            return []
        for route in facts.routes:
            if self._is_health_uri(route.uri or ""):
                return []
        if self._has_static_health_route(facts):
            return []
        return [self.create_finding("Project has no health check route", "routes/web.php", 1, "No /health, /status, or /ping route was found in the route facts.", "Health endpoints give load balancers and uptime monitors a deterministic way to verify the app is alive.", self.fix_suggestion, context="project:health-check", confidence=0.68, tags=["laravel", "architecture", "routes"])]

    @staticmethod
    def _is_health_uri(uri: str) -> bool:
        normalized = ("/" + uri.strip("/")).lower()
        segments = [segment for segment in normalized.split("/") if segment]
        return bool(segments) and segments[-1] in {"health", "status", "ping"}

    @classmethod
    def _has_static_health_route(cls, facts: Facts) -> bool:
        root = Path(facts.project_path or ".")
        for rel_path in facts.files:
            low = rel_path.replace("\\", "/").lower()
            if not low.endswith((".js", ".cjs", ".mjs", ".ts", ".php")):
                continue
            if not any(marker in low for marker in ("route", "server", "app", "index", "health")):
                continue
            path = root / rel_path
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if cls._contains_health_route(content, low):
                return True
        return False

    @classmethod
    def _contains_health_route(cls, content: str, normalized_path: str) -> bool:
        if re.search(
            r"\b(?:app|router|Route)\s*(?:::|\.)(?:get|head|match|any)\s*\(\s*['\"][^'\"]*/(?:health|status|ping)['\"]",
            content,
            flags=re.IGNORECASE,
        ):
            return True
        return bool("health" in normalized_path and re.search(r"\b(?:app|router)\.(?:get|head)\s*\(\s*['\"]/?['\"]", content, flags=re.IGNORECASE))
