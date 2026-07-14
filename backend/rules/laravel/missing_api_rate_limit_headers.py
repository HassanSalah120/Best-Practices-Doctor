from __future__ import annotations

import re
from pathlib import Path

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


class MissingApiRateLimitHeadersRule(Rule):
    id = "missing-api-rate-limit-headers"
    name = "Missing API Rate Limit Headers"
    description = "Detects throttled API routes where rate-limit response headers may be stripped or absent"
    category = Category.OBSERVABILITY
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
        # Laravel's ThrottleRequests middleware emits quota/retry headers.
        # Absence of duplicated application code is not evidence that those
        # framework headers are missing.  Only report concrete stripping.
        stripping = self._find_rate_limit_header_stripping(facts)
        if not throttled or stripping is None:
            return []

        strip_file, strip_line = stripping
        return [
            self.create_finding(
                title="Throttled API routes should preserve rate-limit headers",
                file=strip_file,
                line_start=strip_line,
                context="api:rate-limit-headers",
                description=(
                    "Application code explicitly removes a rate-limit or retry header from a throttled API response."
                ),
                why_it_matters=(
                    "API clients need quota and retry headers to back off before repeated 429 responses."
                ),
                suggested_fix=self.fix_suggestion,
                confidence=0.60,
                tags=["laravel", "api", "rate-limit"],
                evidence_signals=["api_throttle_middleware=true", "rate_limit_header_stripping=true"],
            ),
        ]

    def _is_api_route(self, route: object) -> bool:
        from rules.laravel._route_helpers import is_api_route_file
        uri = str(getattr(route, "uri", "") or "").strip("/").lower()
        if uri.startswith("api/"):
            return True
        if "api" in " ".join(str(mw or "").lower() for mw in getattr(route, "middleware", []) or []):
            return True
        fp = str(getattr(route, "file_path", "") or "").replace("\\", "/").lower()
        return is_api_route_file(fp)

    def _find_rate_limit_header_stripping(self, facts: Facts) -> tuple[str, int] | None:
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
            pattern = re.compile(
                r"(?:withoutHeader|removeHeader|headers->remove)\s*\(\s*['\"]"
                r"(?:X-RateLimit(?:-[A-Za-z-]+)?|Retry-After)['\"]",
                re.IGNORECASE,
            )
            match = pattern.search(text)
            if match:
                return norm, text.count("\n", 0, match.start()) + 1
        return None
