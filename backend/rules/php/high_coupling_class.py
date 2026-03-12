"""
High Coupling Class Rule

Flags classes with too many outgoing dependencies in the App\\* namespace.
"""

from __future__ import annotations

from analysis.dependency_graph import get_dependency_graph
from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class HighCouplingClassRule(Rule):
    id = "high-coupling-class"
    name = "High Coupling Class"
    description = "Detects classes that depend on too many other application classes"
    category = Category.ARCHITECTURE
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
        g = get_dependency_graph(facts)
        max_outgoing = int(self.get_threshold("max_outgoing", 12))

        classes_by_fqcn = {c.fqcn.lstrip("\\"): c for c in facts.classes if c.fqcn}
        app_nodes = {fqcn for fqcn in g.nodes if fqcn.startswith("App\\")}
        if not app_nodes:
            return []

        findings: list[Finding] = []
        for n in sorted(app_nodes):
            # Skip service providers - they are intentionally high-coupling by design
            if "ServiceProvider" in n or n.startswith("App\\Providers"):
                continue

            deps = sorted(d for d in g.outgoing.get(n, set()) if d in app_nodes)
            if len(deps) <= max_outgoing:
                continue

            c = classes_by_fqcn.get(n)
            file_path = c.file_path if c else ""
            line_start = c.line_start if c else 1
            dep_preview = "\n".join(f"- {d}" for d in deps[:20]) + ("\n- ..." if len(deps) > 20 else "")

            findings.append(
                self.create_finding(
                    title="Class has high coupling",
                    context=n,
                    file=file_path,
                    line_start=line_start,
                    line_end=c.line_end if c else None,
                    description=(
                        f"Class `{n}` has {len(deps)} outgoing dependencies to other App\\* classes "
                        f"(threshold: {max_outgoing}).\n\nDependencies:\n{dep_preview}"
                    ),
                    why_it_matters=(
                        "Highly coupled classes are harder to test and refactor because changes ripple across many "
                        "collaborators. High coupling often indicates missing abstractions or mixed responsibilities."
                    ),
                    suggested_fix=(
                        "1. Split responsibilities into smaller classes (Services for workflows, Actions for steps)\n"
                        "2. Introduce interfaces to depend on contracts, not concretes\n"
                        "3. Extract data access into repositories/query objects\n"
                        "4. Consider events to decouple side effects"
                    ),
                    related_files=[],
                    related_methods=deps,  # evidence: dependencies
                    tags=["architecture", "coupling"],
                    confidence=0.6,
                )
            )

        return findings
