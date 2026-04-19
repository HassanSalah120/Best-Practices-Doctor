"""
Action Class Naming Consistency Rule.

Mixed-style mode: emits only when both `*Action` and non-suffixed action class
names coexist under `app/Actions`.
"""

from __future__ import annotations

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Category, Finding, FindingClassification, Severity
from rules.base import Rule
from core.project_recommendations import recommendation_context_tags


class ActionClassNamingConsistencyRule(Rule):
    id = "action-class-naming-consistency"
    name = "Action Class Naming Consistency"
    description = "Detects mixed action class naming style under app/Actions"
    category = Category.ARCHITECTURE
    default_severity = Severity.LOW
    default_classification = FindingClassification.ADVISORY
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
        action_classes = [
            cls
            for cls in facts.classes
            if "/actions/" in str(cls.file_path or "").replace("\\", "/").lower()
        ]
        if len(action_classes) < 2:
            return []

        suffix_classes = [cls for cls in action_classes if str(cls.name or "").endswith("Action")]
        non_suffix_classes = [cls for cls in action_classes if not str(cls.name or "").endswith("Action")]

        # Mixed-style mode: do not fire if project is consistently one style.
        if not suffix_classes or not non_suffix_classes:
            return []

        findings: list[Finding] = []
        suffix_count = len(suffix_classes)
        non_suffix_count = len(non_suffix_classes)
        max_findings_per_file = max(1, int(self.get_threshold("max_findings_per_file", 20) or 20))
        emitted = 0

        for cls in non_suffix_classes:
            if emitted >= max_findings_per_file:
                break

            decision_profile = {
                "decision": "emit",
                "decision_summary": (
                    f"Mixed action naming detected: {suffix_count} suffixed and "
                    f"{non_suffix_count} non-suffixed action classes."
                ),
                "decision_reasons": [
                    f"suffix_count={suffix_count}",
                    f"non_suffix_count={non_suffix_count}",
                    "mixed_style_mode=true",
                ],
                "action_naming_mixed_style": True,
            }

            findings.append(
                self.create_finding(
                    title="Action class naming is inconsistent",
                    context=cls.fqcn or cls.name,
                    file=cls.file_path,
                    line_start=int(cls.line_start or 1),
                    line_end=int(cls.line_end or 0) or None,
                    description=(
                        f"Action class `{cls.name}` does not use the `Action` suffix while this project "
                        "also contains suffixed action class names."
                    ),
                    why_it_matters=(
                        "Mixed naming conventions make action discovery and onboarding harder. "
                        "Consistent naming improves searchability and architectural clarity."
                    ),
                    suggested_fix=(
                        "Rename this class (and file) to use a consistent action suffix, for example:\n"
                        f"- `{cls.name}` -> `{cls.name}Action`\n"
                        "Then update references/imports accordingly."
                    ),
                    tags=["architecture", "actions", "naming", *recommendation_context_tags(facts)],
                    confidence=0.9,
                    evidence_signals=[
                        "action_naming_mixed_style=true",
                        f"suffix_count={suffix_count}",
                        f"non_suffix_count={non_suffix_count}",
                    ],
                    metadata={
                        "action_naming_mixed_style": True,
                        "suffix_count": suffix_count,
                        "non_suffix_count": non_suffix_count,
                        "decision_profile": decision_profile,
                    },
                )
            )
            emitted += 1

        return findings
