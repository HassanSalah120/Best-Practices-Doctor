"""
Sensitive Response Cache-Control Missing Rule

Detects sensitive authenticated routes without explicit no-store style cache controls.
"""

from __future__ import annotations

from schemas.facts import Facts, MethodInfo, RouteInfo
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class SensitiveResponseCacheControlMissingRule(Rule):
    id = "sensitive-response-cache-control-missing"
    name = "Sensitive Response Missing Cache-Control"
    description = "Detects sensitive/authenticated responses without explicit no-store cache headers"
    category = Category.SECURITY
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.RISK
    type = "ast"

    _SENSITIVE_URI_TOKENS = ("account", "profile", "billing", "invoice", "payment", "settings", "portal")
    _AUTH_MIDDLEWARE_TOKENS = ("auth", "sanctum", "verified")
    _CACHE_HARDENING_MIDDLEWARE_TOKENS = (
        "no.store",
        "nostore",
        "no-store",
        "cache.headers",
        "cache-control",
        "cache.control",  # Laravel middleware alias (dot notation)
        "nocache",
        "no_cache",
    )
    _CACHE_CONTROL_SIGNALS = ("cache-control", "no-store", "private, no-cache", "->header(")

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)

        for route in facts.routes or []:
            if not self._is_sensitive_route(route):
                continue
            if self._has_cache_hardening_middleware(route):
                continue
            method = self._resolve_method(route, facts.methods or [])
            if method is None:
                continue
            if self._has_cache_control(method):
                continue
            confidence = 0.8
            if confidence + 1e-9 < min_confidence:
                continue
            findings.append(
                self.create_finding(
                    title="Sensitive response missing explicit cache-control hardening",
                    context=f"{route.method.upper()} {route.uri}",
                    file=route.file_path or method.file_path,
                    line_start=int(route.line_number or method.line_start or 1),
                    description=(
                        f"Sensitive route `{route.method.upper()} {route.uri}` does not show explicit no-store style cache header handling."
                    ),
                    why_it_matters="Cached sensitive responses can leak account or billing data on shared browsers/proxies.",
                    suggested_fix="Set `Cache-Control: no-store, private` (or equivalent) on sensitive authenticated response paths.",
                    related_methods=[method.method_fqn],
                    confidence=confidence,
                    tags=["laravel", "security", "cache-control", "privacy"],
                    evidence_signals=["sensitive_route=true", "cache_control_header_missing=true"],
                )
            )
        return findings

    def _is_sensitive_route(self, route: RouteInfo) -> bool:
        method = str(route.method or "").strip().lower()
        if method not in {"get", "post", "put", "patch", "delete"}:
            return False
        middleware = " ".join(str(m or "").lower() for m in (route.middleware or []))
        if not any(tok in middleware for tok in self._AUTH_MIDDLEWARE_TOKENS):
            return False
        uri = str(route.uri or "").lower()
        return any(tok in uri for tok in self._SENSITIVE_URI_TOKENS)

    def _resolve_method(self, route: RouteInfo, methods: list[MethodInfo]) -> MethodInfo | None:
        target_action = str(route.action or "").strip()
        if "@" in target_action:
            target_action = target_action.rsplit("@", 1)[-1]
        target_action_low = target_action.lower()
        target_controller = str(route.controller or "").strip().split("\\")[-1].replace("Controller", "").lower()
        for method in methods:
            if str(method.name or "").lower() != target_action_low:
                continue
            class_name = str(method.class_name or "").replace("Controller", "").lower()
            class_fqcn = str(method.class_fqcn or "").replace("Controller", "").lower()
            if target_controller and target_controller not in class_name and target_controller not in class_fqcn:
                continue
            return method
        return None

    def _has_cache_hardening_middleware(self, route: RouteInfo) -> bool:
        middleware_tokens = [str(token or "").lower() for token in (route.middleware or [])]
        for middleware in middleware_tokens:
            # Check raw middleware name against tokens
            if any(signal in middleware for signal in self._CACHE_HARDENING_MIDDLEWARE_TOKENS):
                return True
            # Normalize: remove separators (dots, dashes, underscores) for fuzzy matching
            normalized = "".join(ch for ch in middleware if ch.isalnum())
            if "nostore" in normalized and "middleware" in normalized:
                return True
            if "nostorecache" in normalized:
                return True
            # Also check for cachecontrol pattern (handles cache-control, cache.control, cache_control)
            if "cachecontrol" in normalized:
                return True
        return False

    def _has_cache_control(self, method: MethodInfo) -> bool:
        calls = [str(c or "").lower() for c in (method.call_sites or [])]
        return any(
            ("->header(" in call and "cache-control" in call)
            or "responsenostore" in call
            or "withheaders" in call and "cache-control" in call
            for call in calls
        ) or any(any(sig in call for sig in self._CACHE_CONTROL_SIGNALS) for call in calls)
