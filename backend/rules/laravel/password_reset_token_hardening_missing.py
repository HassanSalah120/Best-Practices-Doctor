"""
Password Reset Token Hardening Missing Rule

Detects custom password reset handlers without obvious token hardening flow.
"""

from __future__ import annotations

from schemas.facts import Facts, MethodInfo, RouteInfo
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class PasswordResetTokenHardeningMissingRule(Rule):
    id = "password-reset-token-hardening-missing"
    name = "Password Reset Token Hardening Missing"
    description = "Detects reset-password handlers missing visible broker/token hardening flow"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "ast"

    _RESET_URI_TOKENS = ("reset-password", "password/reset", "forgot-password", "password.update")
    _SAFE_FLOW_SIGNALS = ("password::reset(", "broker()->reset(", "passwordbroker", "resettokens")
    _TOKEN_USAGE_SIGNALS = ("token", "password", "email")

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)

        for route in facts.routes or []:
            if not self._is_reset_route(route):
                continue
            method = self._resolve_method(route, facts.methods or [])
            if method is None:
                continue
            if self._has_safe_reset_flow(method):
                continue
            if not self._appears_to_handle_reset_token(method):
                continue
            confidence = 0.84
            if confidence + 1e-9 < min_confidence:
                continue
            findings.append(
                self.create_finding(
                    title="Password reset handler lacks visible token hardening flow",
                    context=f"{route.method.upper()} {route.uri}",
                    file=route.file_path or method.file_path,
                    line_start=int(route.line_number or method.line_start or 1),
                    description="Detected custom reset-password flow without visible password broker/token lifecycle handling.",
                    why_it_matters="Weak token lifecycle handling can allow replay or stale-token account takeover.",
                    suggested_fix=(
                        "Use Laravel Password Broker reset flow (hashed tokens, TTL, one-time use) and invalidate prior sessions/tokens on reset."
                    ),
                    related_methods=[method.method_fqn],
                    confidence=confidence,
                    tags=["laravel", "security", "password-reset", "token"],
                    evidence_signals=["password_reset_route=true", "broker_flow_missing=true"],
                )
            )
        return findings

    def _is_reset_route(self, route: RouteInfo) -> bool:
        method = str(route.method or "").strip().lower()
        if method not in {"post", "put", "patch"}:
            return False
        payload = " ".join(
            [
                str(route.uri or "").lower(),
                str(route.name or "").lower(),
                str(route.action or "").lower(),
                str(route.controller or "").lower(),
            ]
        )
        return any(token in payload for token in self._RESET_URI_TOKENS)

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

    def _has_safe_reset_flow(self, method: MethodInfo) -> bool:
        calls = [str(c or "").lower() for c in (method.call_sites or [])]
        return any(any(sig in call for sig in self._SAFE_FLOW_SIGNALS) for call in calls)

    def _appears_to_handle_reset_token(self, method: MethodInfo) -> bool:
        calls = [str(c or "").lower() for c in (method.call_sites or [])]
        joined = " ".join(calls)
        return all(sig in joined for sig in self._TOKEN_USAGE_SIGNALS)

