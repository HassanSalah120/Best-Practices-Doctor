"""
Notification ShouldQueue Missing Rule

Detects notifications that use delivery channels but do not implement ShouldQueue.
"""

from __future__ import annotations

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


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
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Reduce the notification shouldqueue missing by moving expensive work out of hot paths or adding the missing cache/query optimization. Keep the behavior identical and cover the faster path with a focused test.'
    examples = {}
    priority = 3
    group = 'Performance'
    applies_to = ['job']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'ast'
    analysis_cost = 'medium'
    auto_fixable = False
    tags = {'domain': 'laravel', 'type': 'performance', 'concern': 'notification-shouldqueue'}

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

        # Build inheritance maps for checking parent classes (robust against alias/short-name lookups).
        class_by_fqcn, class_by_short_name = self._build_class_indexes(getattr(facts, "classes", []) or [])

        for notification in notifications:
            if self._implements_shouldqueue(notification.implements or []):
                continue

            # Check if any parent class implements ShouldQueue
            if self._parent_implements_shouldqueue(notification, class_by_fqcn, class_by_short_name):
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
                },
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
                ),
            )

        return findings

    def _notifications_context_enabled(self, facts: Facts) -> bool:
        payload = (getattr(getattr(facts, "project_context", None), "backend_capabilities", {}) or {}).get(
            "notifications_heavy",
            {},
        )
        return isinstance(payload, dict) and bool(payload.get("enabled", False))

    def _parent_implements_shouldqueue(self, notification, class_by_fqcn: dict[str, object], class_by_short_name: dict[str, list[object]]) -> bool:
        """Check if any parent class in inheritance chain implements ShouldQueue."""
        visited = set()
        own_class = self._resolve_class_ref(str(getattr(notification, "fqcn", "") or ""), class_by_fqcn, class_by_short_name)
        parent_ref = str(getattr(notification, "extends", "") or "").strip()
        if not parent_ref and own_class is not None:
            parent_ref = str(getattr(own_class, "extends", "") or "").strip()

        while parent_ref:
            parent_key = self._normalize_symbol(parent_ref)
            if not parent_key or parent_key in visited:
                break
            visited.add(parent_key)

            parent_class = self._resolve_class_ref(parent_ref, class_by_fqcn, class_by_short_name)
            if not parent_class:
                break

            if self._implements_shouldqueue(getattr(parent_class, "implements", []) or []):
                return True

            parent_ref = str(getattr(parent_class, "extends", "") or "").strip()

        return False

    def _implements_shouldqueue(self, interfaces: list[str]) -> bool:
        for item in interfaces or []:
            normalized = self._normalize_symbol(item)
            if normalized == "shouldqueue" or normalized.endswith("\\shouldqueue"):
                return True
        return False

    def _build_class_indexes(self, classes: list[object]) -> tuple[dict[str, object], dict[str, list[object]]]:
        by_fqcn: dict[str, object] = {}
        by_short: dict[str, list[object]] = {}
        for cls in classes:
            fqcn = self._normalize_symbol(getattr(cls, "fqcn", "") or "")
            if not fqcn:
                continue
            by_fqcn[fqcn] = cls
            short = fqcn.rsplit("\\", 1)[-1]
            by_short.setdefault(short, []).append(cls)
        return by_fqcn, by_short

    def _resolve_class_ref(self, ref: str, by_fqcn: dict[str, object], by_short: dict[str, list[object]]) -> object | None:
        normalized = self._normalize_symbol(ref)
        if not normalized:
            return None
        direct = by_fqcn.get(normalized)
        if direct is not None:
            return direct

        short = normalized.rsplit("\\", 1)[-1]
        short_hits = by_short.get(short, [])
        if len(short_hits) == 1:
            return short_hits[0]

        suffix = "\\" + normalized
        suffix_hits = [cls for key, cls in by_fqcn.items() if key.endswith(suffix)]
        if len(suffix_hits) == 1:
            return suffix_hits[0]
        return None

    def _normalize_symbol(self, value: str) -> str:
        return str(value or "").strip().lstrip("\\").lower()
