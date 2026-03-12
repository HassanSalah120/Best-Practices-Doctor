"""
Action Class Suggestion Rule

Suggests converting single-method services into Action classes (use-case oriented).
"""
from schemas.facts import Facts, ClassInfo, MethodInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class ActionClassSuggestionRule(Rule):
    id = "action-class-suggestion"
    name = "Action Class Suggestion"
    description = "Suggests an Action class when a service has a single public method"
    category = Category.ARCHITECTURE
    default_severity = Severity.LOW
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
        findings: list[Finding] = []

        # Heuristic: treat classes under app/Services as "services".
        services = [c for c in facts.classes if "/services/" in (c.file_path or "").lower()]
        if not services:
            return findings

        methods_by_class: dict[str, list[MethodInfo]] = {}
        for m in facts.methods:
            if not m.class_fqcn:
                continue
            methods_by_class.setdefault(m.class_fqcn, []).append(m)

        for svc in services:
            ms = methods_by_class.get(svc.fqcn, [])
            publics = [
                m for m in ms
                if (m.visibility or "public") == "public"
                and not m.name.startswith("__")
            ]

            # Ignore "utility" public methods that are likely framework hooks.
            publics = [m for m in publics if m.name not in {"boot", "register"}]

            if len(publics) != 1:
                continue

            # Skip services that implement interfaces - they are part of contract-based architecture
            if svc.implements and len(svc.implements) > 0:
                continue

            # Skip abstract classes - they are base classes used via inheritance
            if getattr(svc, "is_abstract", False):
                continue

            only = publics[0]
            ctx = svc.fqcn
            findings.append(
                self.create_finding(
                    title="Single-method service: consider an Action class",
                    context=ctx,
                    file=svc.file_path,
                    line_start=svc.line_start,
                    line_end=svc.line_end,
                    description=(
                        f"Service `{svc.name}` has a single public method `{only.name}`. "
                        "This often represents a single use-case and can be modeled as an Action class."
                    ),
                    why_it_matters=(
                        "Action classes make use-cases explicit, improve naming, and reduce the tendency for "
                        "Services to become god-objects over time. They also compose well in controllers and jobs."
                    ),
                    suggested_fix=(
                        "Rule of thumb:\n"
                        "- If the operation is reusable, small, and used in more than one place/service: prefer an Action.\n"
                        "- If it represents a full workflow/use-case with multiple steps: keep it as a Service.\n"
                        "\n"
                        "1. Create an Action class under `App\\Actions\\...`\n"
                        "2. Move the single public method logic into `__invoke()` or a single `handle()` method\n"
                        "3. Inject dependencies via constructor\n"
                        "4. Update call sites to use the Action"
                    ),
                    tags=["architecture", "actions", "services"],
                    confidence=0.7,
                )
            )

        return findings
