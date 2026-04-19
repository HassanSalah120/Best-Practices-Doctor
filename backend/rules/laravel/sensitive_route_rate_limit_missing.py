"""
Sensitive Route Rate Limit Missing Rule

Detects public/auth-sensitive routes that are missing throttle/rate-limit middleware.
"""

from __future__ import annotations

from schemas.facts import Facts, RouteInfo
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class SensitiveRouteRateLimitMissingRule(Rule):
    id = "sensitive-route-rate-limit-missing"
    name = "Sensitive Route Rate Limit Missing"
    description = "Detects sensitive public routes missing throttle middleware"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "ast"

    _SENSITIVE_TOKENS = (
        "login",
        "register",
        "password",
        "forgot",
        "reset",
        "token",
        "otp",
        "2fa",
        "two-factor",
        "verification",
        "verify-email",
        "invite",
        "magic-link",
        "resend",
    )
    _RATE_LIMIT_TOKENS = ("throttle", "rate", "limiter")
    _MUTATING_METHODS = {"post", "put", "patch", "delete"}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        require_public_surface = bool(self.get_threshold("require_public_surface_capability", False))
        if require_public_surface and not self._has_public_surface_capability(facts):
            return []

        findings: list[Finding] = []
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)

        for route in facts.routes or []:
            if not self._route_is_sensitive(route):
                continue
            if self._has_rate_limit(route):
                continue

            confidence = 0.84
            method = str(route.method or "").strip().lower()
            if method in self._MUTATING_METHODS:
                confidence += 0.04
            confidence = min(0.92, confidence)
            if confidence + 1e-9 < min_confidence:
                continue

            findings.append(
                self.create_finding(
                    title="Sensitive route appears to miss rate limiting",
                    context=f"{str(route.method or '').upper()} {route.uri}",
                    file=route.file_path or "routes/web.php",
                    line_start=int(getattr(route, "line_number", 1) or 1),
                    description=(
                        f"Detected sensitive route `{str(route.method or '').upper()} {route.uri}` without throttle/rate-limit middleware."
                    ),
                    why_it_matters=(
                        "Authentication and account-recovery endpoints are frequent brute-force and abuse targets without request throttling."
                    ),
                    suggested_fix=(
                        "Apply route-level throttling (for example `throttle:6,1` or named rate limiters) to sensitive public endpoints."
                    ),
                    tags=["laravel", "security", "rate-limit", "auth", "abuse-prevention"],
                    confidence=confidence,
                    evidence_signals=[
                        f"route={str(route.method or '').upper()} {route.uri}",
                        "sensitive_route=true",
                        "rate_limit_middleware_missing=true",
                    ],
                )
            )

        return findings

    def _route_is_sensitive(self, route: RouteInfo) -> bool:
        method = str(route.method or "").strip().lower()
        if method not in {"post", "put", "patch", "delete", "get"}:
            return False

        payload = " ".join(
            [
                str(route.uri or "").lower(),
                str(route.controller or "").lower(),
                str(route.action or "").lower(),
                str(route.name or "").lower(),
            ]
        )
        if not any(token in payload for token in self._SENSITIVE_TOKENS):
            return False

        middleware_text = " ".join(str(item or "").lower() for item in (route.middleware or []))
        # Public or semi-public auth routes are highest risk; authenticated-only sensitive
        # flows can be ignored here to reduce false positives.
        if "auth" in middleware_text and "guest" not in middleware_text:
            return False
        return True

    def _has_rate_limit(self, route: RouteInfo) -> bool:
        middleware_text = " ".join(str(item or "").lower() for item in (route.middleware or []))
        return any(token in middleware_text for token in self._RATE_LIMIT_TOKENS)

    def _has_public_surface_capability(self, facts: Facts) -> bool:
        return (
            self._capability_enabled(facts, "mixed_public_dashboard")
            or self._capability_enabled(facts, "public_marketing_site")
        )

    def _capability_enabled(self, facts: Facts, key: str) -> bool:
        project_context = getattr(facts, "project_context", None)
        payload = None
        if project_context is not None:
            payload = (getattr(project_context, "capabilities", {}) or {}).get(key)
            if payload is None:
                payload = (getattr(project_context, "backend_capabilities", {}) or {}).get(key)
        return bool(isinstance(payload, dict) and payload.get("enabled"))

