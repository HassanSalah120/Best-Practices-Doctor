"""
Webhook Replay Protection Missing Rule

Detects webhook handlers that validate signatures but do not show replay-window checks.
"""

from __future__ import annotations

from schemas.facts import Facts, MethodInfo, RouteInfo
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class WebhookReplayProtectionMissingRule(Rule):
    id = "webhook-replay-protection-missing"
    name = "Webhook Replay Protection Missing"
    description = "Detects webhook handlers without visible timestamp/nonce replay protection"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "ast"

    _WEBHOOK_TOKENS = ("webhook", "callback", "stripe", "twilio", "paymob")
    _SIGNATURE_SIGNALS = ("validatesignature", "verifysignature", "hmac", "constructevent")
    _REPLAY_SIGNALS = ("timestamp", "nonce", "replay", "cache::add(", "isrecent", "withinwindow")

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        require_integrations = bool(self.get_threshold("require_external_integrations_capability", False))
        if require_integrations and not self._capability_enabled(facts, "external_integrations_heavy"):
            return []

        for route in facts.routes or []:
            if not self._looks_like_webhook(route):
                continue
            method = self._resolve_method(route, facts.methods or [])
            if method is None:
                continue
            if not self._has_signature_validation(method):
                continue
            if self._has_replay_guard(method):
                continue
            confidence = 0.84
            if confidence + 1e-9 < min_confidence:
                continue
            findings.append(
                self.create_finding(
                    title="Webhook handler missing explicit replay protection",
                    context=f"{route.method.upper()} {route.uri}",
                    file=route.file_path or method.file_path,
                    line_start=int(route.line_number or method.line_start or 1),
                    description="Webhook signature checks exist, but no timestamp/nonce replay-window checks were detected.",
                    why_it_matters="Signed payloads can still be replayed if freshness/nonces are not enforced.",
                    suggested_fix=(
                        "Validate provider timestamp tolerance and enforce nonce/event-id deduplication "
                        "(for example cache/store seen IDs for a bounded TTL)."
                    ),
                    related_methods=[method.method_fqn],
                    confidence=confidence,
                    tags=["laravel", "security", "webhook", "replay"],
                    evidence_signals=["signature_validation=true", "replay_guard=false"],
                )
            )
        return findings

    def _looks_like_webhook(self, route: RouteInfo) -> bool:
        method = str(route.method or "").strip().lower()
        if method not in {"post", "put", "patch", "any", "match"}:
            return False
        payload = " ".join(
            [
                str(route.uri or "").lower(),
                str(route.name or "").lower(),
                str(route.controller or "").lower(),
                str(route.action or "").lower(),
            ]
        )
        return any(token in payload for token in self._WEBHOOK_TOKENS)

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

    def _has_signature_validation(self, method: MethodInfo) -> bool:
        calls = [str(c or "").lower() for c in (method.call_sites or [])]
        return any(any(sig in call for sig in self._SIGNATURE_SIGNALS) for call in calls)

    def _has_replay_guard(self, method: MethodInfo) -> bool:
        calls = [str(c or "").lower() for c in (method.call_sites or [])]
        return any(any(sig in call for sig in self._REPLAY_SIGNALS) for call in calls)

    def _capability_enabled(self, facts: Facts, key: str) -> bool:
        project_context = getattr(facts, "project_context", None)
        payload = None
        if project_context is not None:
            capabilities = getattr(project_context, "capabilities", {}) or {}
            payload = capabilities.get(key)
            if payload is None:
                payload = (getattr(project_context, "backend_capabilities", {}) or {}).get(key)
        return bool(isinstance(payload, dict) and payload.get("enabled"))

