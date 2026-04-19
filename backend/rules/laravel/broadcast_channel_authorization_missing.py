"""
Broadcast Channel Authorization Missing Rule

Detects broadcast channels that appear to allow access without authorization checks.
"""

from __future__ import annotations

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class BroadcastChannelAuthorizationMissingRule(Rule):
    id = "broadcast-channel-authorization-missing"
    name = "Broadcast Channel Authorization Missing"
    description = "Detects broadcast channels that do not show explicit authorization logic"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "ast"
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        channels = getattr(facts, "broadcast_channels", []) or []
        if not channels and not self._realtime_context_enabled(facts):
            return []

        findings: list[Finding] = []
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)

        for channel in channels:
            kind = str(channel.authorization_kind or "").lower()
            if kind == "guarded":
                continue
            if kind == "deny_all":
                continue

            confidence = 0.92 if kind == "allow_all" else 0.84
            if confidence + 1e-9 < min_confidence:
                continue

            findings.append(
                self.create_finding(
                    title="Broadcast channel missing explicit authorization",
                    file=channel.file_path,
                    line_start=int(channel.line_number or 1),
                    context=f"broadcast:{channel.channel_name}",
                    description=(
                        f"Broadcast channel `{channel.channel_name}` does not show explicit user-scoped authorization and may allow unintended subscribers."
                    ),
                    why_it_matters=(
                        "Broadcast channels often expose private or presence data. Weak authorization can leak realtime events to unauthorized users."
                    ),
                    suggested_fix="Require a user-scoped authorization callback that checks ownership, membership, or policy authorization before returning true.",
                    confidence=confidence,
                    tags=["laravel", "broadcast", "realtime", "security"],
                    evidence_signals=[
                        "broadcast_channel_detected=true",
                        "broadcast_channel_authorization_missing=true",
                        f"authorization_kind={kind or 'unknown'}",
                    ],
                )
            )

        return findings

    def _realtime_context_enabled(self, facts: Facts) -> bool:
        capabilities = getattr(getattr(facts, "project_context", None), "backend_capabilities", {}) or {}
        realtime = capabilities.get("realtime")
        return isinstance(realtime, dict) and bool(realtime.get("enabled", False))
