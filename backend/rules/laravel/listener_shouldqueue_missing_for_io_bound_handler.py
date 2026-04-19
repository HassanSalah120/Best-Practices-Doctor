"""
Listener ShouldQueue Missing For IO Bound Handler Rule

Detects event listeners that perform obvious IO or side effects without implementing ShouldQueue.
"""

from __future__ import annotations

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class ListenerShouldQueueMissingForIoBoundHandlerRule(Rule):
    id = "listener-shouldqueue-missing-for-io-bound-handler"
    name = "Listener ShouldQueue Missing For IO-Bound Handler"
    description = "Detects listeners that perform IO-heavy work synchronously"
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

    _IO_TOKENS = (
        "mail::",
        "notification::",
        "http::",
        "storage::",
        "broadcast(",
        "dispatch(",
        "->notify(",
        "->send(",
        "->post(",
        "->put(",
        "->delete(",
    )

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        listeners = getattr(facts, "listeners", []) or []
        if not listeners and not self._queue_context_enabled(facts):
            return []

        findings: list[Finding] = []
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)

        for listener in listeners:
            implements = {str(item or "").lower() for item in (listener.implements or [])}
            if "shouldqueue" in implements:
                continue

            handle_method = next(
                (
                    method
                    for method in (getattr(facts, "methods", []) or [])
                    if str(getattr(method, "class_fqcn", "") or "") == str(listener.fqcn or "")
                    and str(getattr(method, "name", "") or "").lower() == "handle"
                ),
                None,
            )
            if handle_method is None:
                continue

            call_sites = [str(call or "").lower() for call in (handle_method.call_sites or [])]
            io_hits = [token for token in self._IO_TOKENS if any(token in call for call in call_sites)]
            if not io_hits:
                continue

            confidence = min(0.95, 0.82 + (0.03 * min(len(io_hits), 3)))
            if confidence + 1e-9 < min_confidence:
                continue

            findings.append(
                self.create_finding(
                    title="IO-heavy listener runs synchronously",
                    file=listener.file_path,
                    line_start=int(handle_method.line_start or listener.line_start or 1),
                    context=f"listener:{listener.name}",
                    description=(
                        f"Listener `{listener.name}` performs IO-heavy work in `handle()` but does not implement `ShouldQueue`."
                    ),
                    why_it_matters=(
                        "Synchronous listeners can slow down event dispatch paths and make failures in mail, HTTP, or notification delivery harder to isolate."
                    ),
                    suggested_fix="Implement `ShouldQueue` for IO-bound listeners or move the side effect into an explicit queued job.",
                    confidence=confidence,
                    tags=["laravel", "listeners", "queue", "performance"],
                    evidence_signals=[
                        "listener_io_work_detected=true",
                        "listener_shouldqueue_missing=true",
                        f"io_signal_count={len(io_hits)}",
                    ],
                )
            )

        return findings

    def _queue_context_enabled(self, facts: Facts) -> bool:
        capabilities = getattr(getattr(facts, "project_context", None), "backend_capabilities", {}) or {}
        for key in ("queue_heavy", "notifications_heavy", "external_integrations_heavy"):
            payload = capabilities.get(key)
            if isinstance(payload, dict) and bool(payload.get("enabled", False)):
                return True
        return False
