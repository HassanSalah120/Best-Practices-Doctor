"""
Webhook Signature Missing Rule

Detects webhook/callback routes that do not show explicit signature verification.
"""

from __future__ import annotations

from schemas.facts import Facts, MethodInfo, RouteInfo
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class WebhookSignatureMissingRule(Rule):
    id = "webhook-signature-missing"
    name = "Webhook Signature Verification Missing"
    description = "Detects webhook handlers lacking visible signature verification"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "ast"

    _WEBHOOK_TOKENS = (
        "webhook",
        "callback",
        "stripe",
        "twilio",
        "paymob",
        "github",
        "slack",
        "provider",
    )
    _SIGNATURE_MIDDLEWARE_TOKENS = (
        "signed",
        "signature",
        "verify.webhook",
        "validate.webhook",
        "webhook.signature",
        "hmac",
    )
    _SIGNATURE_CALL_TOKENS = (
        "validatesignature",
        "verifysignature",
        "hasvalidsignature",
        "signaturevalidator",
        "constructevent",
        "webhooksignature",
        "hmac",
    )

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        require_external_integrations = bool(self.get_threshold("require_external_integrations_capability", False))
        if require_external_integrations and not self._capability_enabled(facts, "external_integrations_heavy"):
            return []

        findings: list[Finding] = []
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)

        for route in facts.routes or []:
            if not self._looks_like_webhook_route(route):
                continue
            if self._has_signature_middleware(route):
                continue

            method = self._resolve_method(route, facts.methods or [])
            if method is None:
                # High-confidence-first: if we cannot resolve handler method, do not fire.
                continue
            if self._method_has_signature_verification(method):
                continue

            confidence = 0.9
            if confidence + 1e-9 < min_confidence:
                continue

            method_ref = method.method_fqn
            findings.append(
                self.create_finding(
                    title="Webhook handler appears to miss signature verification",
                    context=f"{route.method.upper()} {route.uri}",
                    file=route.file_path or method.file_path,
                    line_start=int(getattr(route, "line_number", method.line_start or 1) or 1),
                    description=(
                        f"Detected webhook/callback route `{route.method.upper()} {route.uri}` mapped to `{method_ref}` "
                        "without visible signature validation in middleware or handler code."
                    ),
                    why_it_matters=(
                        "Unsigned webhook handlers can be forged by attackers, leading to unauthorized state changes and payment/integration abuse."
                    ),
                    suggested_fix=(
                        "Add provider signature validation (HMAC/signature header verification) in middleware or the action method, "
                        "and reject invalid signatures before processing payloads."
                    ),
                    related_methods=[method_ref],
                    tags=["laravel", "security", "webhook", "signature", "integrations"],
                    confidence=confidence,
                    evidence_signals=[
                        f"route={route.method.upper()} {route.uri}",
                        f"handler={method_ref}",
                        "signature_middleware_missing=true",
                        "signature_call_missing=true",
                    ],
                )
            )

        return findings

    def _looks_like_webhook_route(self, route: RouteInfo) -> bool:
        method = str(route.method or "").strip().lower()
        if method not in {"post", "put", "patch", "any", "match"}:
            return False
        payload = " ".join(
            [
                str(route.uri or "").lower(),
                str(route.controller or "").lower(),
                str(route.action or "").lower(),
                str(route.name or "").lower(),
            ]
        )
        return any(token in payload for token in self._WEBHOOK_TOKENS)

    def _has_signature_middleware(self, route: RouteInfo) -> bool:
        middleware_text = " ".join(str(item or "").lower() for item in (route.middleware or []))
        return any(token in middleware_text for token in self._SIGNATURE_MIDDLEWARE_TOKENS)

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

    def _method_has_signature_verification(self, method: MethodInfo) -> bool:
        call_sites = [str(call or "").lower() for call in (method.call_sites or [])]
        if not call_sites:
            return False
        return any(
            any(signal in call for signal in self._SIGNATURE_CALL_TOKENS)
            for call in call_sites
        )

    def _capability_enabled(self, facts: Facts, key: str) -> bool:
        project_context = getattr(facts, "project_context", None)
        payload = None
        if project_context is not None:
            capabilities = getattr(project_context, "capabilities", {}) or {}
            payload = capabilities.get(key)
            if payload is None:
                payload = (getattr(project_context, "backend_capabilities", {}) or {}).get(key)
        return bool(isinstance(payload, dict) and payload.get("enabled"))

