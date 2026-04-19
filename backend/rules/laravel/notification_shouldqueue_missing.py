"""
Notification ShouldQueue Missing Rule

Detects notifications that use delivery channels but do not implement ShouldQueue.
"""

from __future__ import annotations

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class NotificationShouldQueueMissingRule(Rule):
    id = "notification-shouldqueue-missing"
    name = "Notification ShouldQueue Missing"
    description = "Detects notifications that deliver mail/database/broadcast payloads without implementing ShouldQueue"
    category = Category.PERFORMANCE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    type = "ast"
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    _DELIVERY_METHODS = {"tomail", "todatabase", "tobroadcast", "tovonage", "toslack", "toarray"}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        notifications = getattr(facts, "notifications", []) or []
        if not notifications and not self._notifications_context_enabled(facts):
            return []

        findings: list[Finding] = []
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        methods = getattr(facts, "methods", []) or []

        for notification in notifications:
            implements = {str(item or "").lower() for item in (notification.implements or [])}
            if "shouldqueue" in implements:
                continue

            class_methods = [
                method
                for method in methods
                if str(getattr(method, "class_fqcn", "") or "") == str(notification.fqcn or "")
            ]
            delivery_methods = sorted(
                {
                    str(method.name or "").lower()
                    for method in class_methods
                    if str(method.name or "").lower() in self._DELIVERY_METHODS
                }
            )
            if not delivery_methods:
                continue

            confidence = min(0.94, 0.8 + (0.03 * min(len(delivery_methods), 3)))
            if confidence + 1e-9 < min_confidence:
                continue

            findings.append(
                self.create_finding(
                    title="Notification delivers work synchronously",
                    file=notification.file_path,
                    line_start=int(notification.line_start or 1),
                    context=f"notification:{notification.name}",
                    description=(
                        f"Notification `{notification.name}` defines delivery methods ({', '.join(delivery_methods)}) but does not implement `ShouldQueue`."
                    ),
                    why_it_matters=(
                        "Queued notifications keep request latency predictable and reduce the chance that slow mail or external channel delivery blocks user-facing work."
                    ),
                    suggested_fix="Implement `ShouldQueue` on the notification when the delivery should run asynchronously.",
                    confidence=confidence,
                    tags=["laravel", "notifications", "queue", "performance"],
                    evidence_signals=[
                        "notification_delivery_methods_detected=true",
                        "notification_shouldqueue_missing=true",
                        f"delivery_method_count={len(delivery_methods)}",
                    ],
                )
            )

        return findings

    def _notifications_context_enabled(self, facts: Facts) -> bool:
        payload = (getattr(getattr(facts, "project_context", None), "backend_capabilities", {}) or {}).get(
            "notifications_heavy",
            {},
        )
        return isinstance(payload, dict) and bool(payload.get("enabled", False))
