"""
Unified missing rate limiting rule.

This rule merges multiple internal detectors into one presentation-level finding id.
"""

from __future__ import annotations

import re

from schemas.facts import Facts, RouteInfo
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule
from rules.laravel.missing_throttle_on_auth_api_routes import MissingThrottleOnAuthApiRoutesRule
from rules.laravel.sensitive_route_rate_limit_missing import SensitiveRouteRateLimitMissingRule


class MissingRateLimitingRule(Rule):
    id = "missing-rate-limiting"
    name = "Missing Rate Limiting"
    description = "Detects sensitive endpoints missing explicit throttle/rate-limit controls"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "ast"

    _PUBLIC_FORM = re.compile(
        r"(^|/)(contact|feedback|support|newsletter|lead|request-demo|demo-request)(/|$)",
        re.IGNORECASE,
    )
    _PASSWORD_RESET = re.compile(r"(^|/)(password|forgot|reset)(/|$)", re.IGNORECASE)
    _AUTH = re.compile(
        r"(^|/)(login|logout|register|verify|verification|token|otp|2fa|session)(/|$)",
        re.IGNORECASE,
    )
    _RATE_LIMIT_TOKEN = re.compile(r"(throttle|rate|limiter)", re.IGNORECASE)
    _MUTATING_METHOD = {"post", "put", "patch", "delete", "any", "match"}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        internal_findings: list[Finding] = []

        auth_api_detector = MissingThrottleOnAuthApiRoutesRule(self.config)
        sensitive_detector = SensitiveRouteRateLimitMissingRule(self.config)
        internal_findings.extend(auth_api_detector.analyze(facts, metrics))
        internal_findings.extend(sensitive_detector.analyze(facts, metrics))

        for route in facts.routes or []:
            endpoint_type = self._endpoint_type(route)
            if endpoint_type not in {"public_form", "password_reset"}:
                continue
            if self._has_rate_limit(route):
                continue
            if not self._is_mutating(route):
                continue

            internal_findings.append(
                self.create_finding(
                    title="Rate limiting missing on sensitive endpoint",
                    context=f"{str(route.method or '').upper()} {route.uri}",
                    file=route.file_path or "routes/web.php",
                    line_start=int(getattr(route, "line_number", 1) or 1),
                    description=(
                        f"Detected `{str(route.method or '').upper()} {route.uri}` without explicit throttling."
                    ),
                    why_it_matters=(
                        "Sensitive public endpoints are brute-force and abuse targets without request rate limiting."
                    ),
                    suggested_fix=(
                        "Attach throttle middleware (for example `throttle:6,1` or a named limiter) "
                        "on the route or enclosing route group."
                    ),
                    confidence=0.86 if endpoint_type == "password_reset" else 0.78,
                    tags=["laravel", "security", "throttle", endpoint_type],
                    evidence_signals=[
                        f"endpoint_type={endpoint_type}",
                        f"method={str(route.method or '').upper()}",
                        "rate_limit_middleware_missing=true",
                    ],
                    metadata={"endpoint_type": endpoint_type, "source_detector": "route-heuristic"},
                )
            )

        normalized: list[Finding] = []
        seen: set[str] = set()
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        for finding in internal_findings:
            endpoint_type = self._endpoint_type_from_finding(finding)
            severity = self._severity_for_endpoint(endpoint_type)
            confidence = float(getattr(finding, "confidence", 0.0) or 0.0)
            if confidence + 1e-9 < min_confidence:
                continue

            metadata = dict(getattr(finding, "metadata", {}) or {})
            metadata["endpoint_type"] = endpoint_type
            metadata["source_rule_id"] = finding.rule_id

            updated = finding.model_copy(
                update={
                    "rule_id": self.id,
                    "severity": severity,
                    "title": "Rate limiting missing on sensitive endpoint",
                    "description": self._description_for_endpoint(endpoint_type, finding),
                    "metadata": metadata,
                }
            )
            fp = updated.compute_fingerprint()
            if fp in seen:
                continue
            seen.add(fp)
            normalized.append(updated.model_copy(update={"fingerprint": fp, "id": f"finding_{fp}"}))
        return normalized

    def _endpoint_type(self, route: RouteInfo) -> str:
        uri = str(route.uri or "").strip().strip("/")
        uri_low = uri.lower()
        if self._PASSWORD_RESET.search(uri_low):
            return "password_reset"
        if self._AUTH.search(uri_low):
            return "auth"
        if self._PUBLIC_FORM.search(uri_low):
            return "public_form"
        if uri_low.startswith("api/") or "routes/api.php" in str(route.file_path or "").replace("\\", "/").lower():
            return "api"
        return "api"

    def _endpoint_type_from_finding(self, finding: Finding) -> str:
        metadata = getattr(finding, "metadata", {}) or {}
        endpoint_type = str(metadata.get("endpoint_type", "") or "").strip().lower()
        if endpoint_type in {"public_form", "auth", "password_reset", "api"}:
            return endpoint_type
        context = str(getattr(finding, "context", "") or "").lower()
        if self._PASSWORD_RESET.search(context):
            return "password_reset"
        if self._AUTH.search(context):
            return "auth"
        if self._PUBLIC_FORM.search(context):
            return "public_form"
        if "/api" in context:
            return "api"
        return "api"

    def _has_rate_limit(self, route: RouteInfo) -> bool:
        payload = " ".join(str(item or "") for item in (route.middleware or []))
        return bool(self._RATE_LIMIT_TOKEN.search(payload))

    def _is_mutating(self, route: RouteInfo) -> bool:
        method = str(route.method or "").strip().lower()
        if method in self._MUTATING_METHOD:
            return True
        if "|" in method:
            return any(part.strip() in self._MUTATING_METHOD for part in method.split("|"))
        if "," in method:
            return any(part.strip() in self._MUTATING_METHOD for part in method.split(","))
        return False

    def _severity_for_endpoint(self, endpoint_type: str) -> Severity:
        if endpoint_type in {"auth", "password_reset"}:
            return Severity.HIGH
        if endpoint_type == "api":
            return Severity.MEDIUM
        return Severity.MEDIUM

    def _description_for_endpoint(self, endpoint_type: str, finding: Finding) -> str:
        context = str(getattr(finding, "context", "") or "").strip()
        if endpoint_type == "password_reset":
            return f"Password reset flow `{context}` appears to miss explicit throttling."
        if endpoint_type == "auth":
            return f"Authentication endpoint `{context}` appears to miss explicit throttling."
        if endpoint_type == "public_form":
            return f"Public form endpoint `{context}` appears to miss explicit throttling."
        return f"API endpoint `{context}` appears to miss explicit throttling."
