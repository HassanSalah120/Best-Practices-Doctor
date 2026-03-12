"""
Massive Model Rule

Detects Eloquent models that have grown too large (too many methods / mixed responsibilities).
"""
from schemas.facts import Facts, ClassInfo, MethodInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class MassiveModelRule(Rule):
    id = "massive-model"
    name = "Massive Model Detection"
    description = "Detects models that contain too much logic (consider service/repository extraction)"
    category = Category.MAINTAINABILITY
    default_severity = Severity.MEDIUM
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

        max_methods = int(self.get_threshold("max_methods", 15))
        max_loc = int(self.get_threshold("max_loc", 400))

        methods_by_class: dict[str, list[MethodInfo]] = {}
        for m in facts.methods:
            if not m.class_fqcn:
                continue
            methods_by_class.setdefault(m.class_fqcn, []).append(m)

        for model in facts.models:
            ms = methods_by_class.get(model.fqcn, [])
            # Exclude magic methods.
            ms = [m for m in ms if not m.name.startswith("__")]
            method_count = len(ms)
            loc = max(0, (model.line_end or 0) - (model.line_start or 0) + 1)

            if method_count <= max_methods and loc <= max_loc:
                continue

            # Best-effort: how many methods look like they contain DB logic/business logic.
            queryish = 0
            businessish = 0
            if metrics:
                for m in ms:
                    mm = metrics.get(m.method_fqn)
                    if not mm:
                        continue
                    if mm.has_query:
                        queryish += 1
                    if mm.has_business_logic:
                        businessish += 1

            ctx = model.fqcn
            findings.append(
                self.create_finding(
                    title="Model is too large; consider extracting responsibilities",
                    context=ctx,
                    file=model.file_path,
                    line_start=model.line_start,
                    line_end=model.line_end,
                    description=(
                        f"Model `{model.name}` appears large (methods={method_count} (threshold: {max_methods}), "
                        f"LOC={loc} (threshold: {max_loc})). "
                        + (f"Detected {queryish} query-ish method(s) and {businessish} business-ish method(s)." if metrics else "")
                    ),
                    why_it_matters=(
                        "Massive models tend to mix concerns (persistence, domain logic, querying, formatting) which makes "
                        "changes riskier and harder to test. Extracting services/repositories improves cohesion."
                    ),
                    suggested_fix=(
                        "1. Extract query logic to a Repository/Query object\n"
                        "2. Extract domain workflows to Services/Actions\n"
                        "3. Keep the model focused on relationships, casts, and invariants\n"
                        "4. Add tests around extracted behavior"
                    ),
                    tags=["maintainability", "models", "srp", "laravel"],
                    confidence=0.65,
                )
            )

        return findings

