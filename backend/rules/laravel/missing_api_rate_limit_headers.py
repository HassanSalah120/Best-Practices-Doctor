from __future__ import annotations

from pathlib import Path

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


class MissingApiRateLimitHeadersRule(Rule):
    id = "missing-api-rate-limit-headers"
    name = "Missing API Rate Limit Headers"
    description = "Detects throttled API routes where rate-limit response headers may be stripped or absent"
    category = Category.LARAVEL_BEST_PRACTICE
    default_severity = Severity.LOW
    default_classification = FindingClassification.ADVISORY
    type = "ast"
    severity_weight = 2
    confidence = "low"
    fix_suggestion = (
        "Laravel's ThrottleRequests middleware includes X-RateLimit-* headers by default. Ensure your "
        "custom rate limiter or response wrapper does not strip them."
    )
    examples = {
        "bad": "Route::middleware('throttle:api')->group(...); // custom response layer strips headers",
        "good": "429 responses preserve X-RateLimit-Limit, X-RateLimit-Remaining, and Retry-After headers.",
    }
    priority = 4
    group = "API Design"
    applies_to = ["route", "middleware"]
    references = ["RFC 6585 - 429 Too Many Requests"]
    related_rules = ["missing-rate-limiting", "sensitive-route-rate-limit-missing"]
    false_positive_notes = (
        "Laravel emits rate-limit headers by default. This is low-confidence and should be reviewed when "
        "custom middleware or API response wrappers are present."
    )
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "quality", "concern": "rate-limit-headers"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        throttled = [
            route
            for route in getattr(facts, "routes", []) or []
            if self._is_api_route(route) and any("throttle" in str(mw).lower() for mw in route.middleware or [])
        ]
        if not throttled or self._has_rate_limit_header_signal(facts):
            return []

        route = throttled[0]
        return [
            self.create_finding(
                title="Throttled API routes should preserve rate-limit headers",
                file=route.file_path or "routes/api.php",
                line_start=int(getattr(route, "line_number", 1) or 1),
                context="api:rate-limit-headers",
                description=(
                    "Throttle middleware is applied to API routes, but no repository-visible rate-limit header "
                    "configuration or tests were found."
                ),
                why_it_matters=(
                    "API clients need quota and retry headers to back off before repeated 429 responses."
                ),
                suggested_fix=self.fix_suggestion,
                confidence=0.45,
                tags=["laravel", "api", "rate-limit"],
                evidence_signals=["api_throttle_middleware=true", "rate_limit_header_signal=false"],
            ),
        ]

    def _is_api_route(self, route: object) -> bool:
        uri = str(getattr(route, "uri", "") or "").strip("/").lower()
        path = str(getattr(route, "file_path", "") or "").replace("\\", "/").lower()
        middleware = " ".join(str(mw or "").lower() for mw in getattr(route, "middleware", []) or [])
        return uri.startswith("api/") or "routes/api.php" in path or "api" in middleware

    def _has_rate_limit_header_signal(self, facts: Facts) -> bool:
        root = Path(getattr(facts, "project_path", "") or ".")
        files = list(getattr(facts, "files", []) or [])
        if not files:
            try:
                files = [path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()]
            except Exception:
                files = []
        for rel in files:
            norm = str(rel).replace("\\", "/")
            if not norm.endswith((".php", ".ts", ".tsx", ".js", ".jsx")):
                continue
            if any(part in norm for part in ("vendor/", "node_modules/")):
                continue
            try:
                text = (root / norm).read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            low = text.lower()
            if "x-ratelimit" in low or "x-ratelimit-" in low or "retry-after" in low:
                return True
        return False
