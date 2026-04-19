"""
Observer Heavy Logic Rule

Detects observers that appear to host too much business logic directly.
"""

from __future__ import annotations

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class ObserverHeavyLogicRule(Rule):
    id = "observer-heavy-logic"
    name = "Observer Heavy Logic"
    description = "Detects observers with large or side-effect-heavy hook methods"
    category = Category.ARCHITECTURE
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

    _HOOK_METHODS = {"creating", "created", "updating", "updated", "saving", "saved", "deleting", "deleted", "restoring", "restored"}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        methods = getattr(facts, "methods", []) or []
        max_method_loc = int(self.get_threshold("max_method_loc", 35) or 35)
        max_side_effect_calls = int(self.get_threshold("max_side_effect_calls", 6) or 6)

        for observer in (getattr(facts, "observers", []) or []):
            observer_methods = [
                method
                for method in methods
                if str(getattr(method, "class_fqcn", "") or "") == str(observer.fqcn or "")
                and str(getattr(method, "name", "") or "").lower() in self._HOOK_METHODS
            ]
            if not observer_methods:
                continue

            oversized = [method for method in observer_methods if int(getattr(method, "loc", 0) or 0) >= max_method_loc]
            side_effect_heavy = [
                method
                for method in observer_methods
                if len(getattr(method, "call_sites", []) or []) >= max_side_effect_calls
            ]
            if not oversized and not side_effect_heavy:
                continue

            signal_count = len({method.method_fqn for method in oversized + side_effect_heavy})
            confidence = min(0.94, 0.78 + (0.04 * min(signal_count, 3)))

            findings.append(
                self.create_finding(
                    title="Observer contains heavy inline business logic",
                    file=observer.file_path,
                    line_start=int(observer.line_start or 1),
                    context=f"observer:{observer.name}",
                    description=(
                        f"Observer `{observer.name}` appears to host large or side-effect-heavy lifecycle hooks directly."
                    ),
                    why_it_matters=(
                        "Large observers are harder to test and can hide business workflows inside model lifecycle events where failures and ordering are less explicit."
                    ),
                    suggested_fix="Keep observers thin and delegate substantial work to actions, services, or queued jobs.",
                    confidence=confidence,
                    tags=["laravel", "observer", "architecture", "maintainability"],
                    evidence_signals=[
                        "observer_hook_logic_heavy=true",
                        f"oversized_hook_count={len(oversized)}",
                        f"side_effect_hook_count={len(side_effect_heavy)}",
                    ],
                )
            )

        return findings
