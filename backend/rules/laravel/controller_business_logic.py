"""
Controller Business Logic Rule

Flags complex/business logic inside controllers as a layering violation.
Uses derived metrics (complexity + business logic heuristics); does not parse source.
"""
from schemas.facts import Facts, MethodInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class ControllerBusinessLogicRule(Rule):
    """
    Detects controller methods that contain significant business logic.

    Uses MethodMetrics derived from AST:
    - cyclomatic complexity
    - business logic flag/confidence
    """

    id = "controller-business-logic"
    name = "Business Logic In Controller"
    description = "Detects complex/business logic inside controllers"
    category = Category.ARCHITECTURE
    default_severity = Severity.HIGH
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
        if not metrics:
            return findings

        controller_files = {c.file_path for c in facts.controllers}
        if not controller_files:
            return findings

        min_cyclomatic = int(self.get_threshold("min_cyclomatic", 8))
        min_loc = int(self.get_threshold("min_loc", 60))
        min_conf = float(self.get_threshold("min_confidence", 0.6))

        # Best-effort map file -> controller fqcn.
        fqcn_by_file: dict[str, str] = {}
        for c in facts.controllers:
            fqcn_by_file.setdefault(c.file_path, c.fqcn)

        for m in facts.methods:
            if m.file_path not in controller_files:
                continue
            if m.name.startswith("__"):
                continue

            mm = metrics.get(m.method_fqn)
            if not mm:
                continue

            if mm.cyclomatic_complexity < min_cyclomatic and (m.loc or 0) < min_loc:
                continue

            controller_fqcn = fqcn_by_file.get(m.file_path, "")
            ctx = m.method_fqn if controller_fqcn else f"{m.file_path}:{m.name}"

            confidence = 0.65
            if mm.has_business_logic:
                confidence = max(confidence, min(1.0, 0.5 + mm.business_logic_confidence / 2))
            else:
                # Controllers often mix validation/queries with branching; treat CC/LOC as primary signal.
                confidence = max(confidence, min(0.9, 0.5 + (mm.cyclomatic_complexity / 20)))

            findings.append(
                self.create_finding(
                    title="Business logic should be extracted from controller",
                    context=ctx,
                    file=m.file_path,
                    line_start=m.line_start,
                    line_end=m.line_end,
                    description=(
                        f"Controller method `{m.name}` appears to contain business logic "
                        f"(CC={mm.cyclomatic_complexity}, LOC={m.loc}). "
                        "Consider extracting this logic into a Service or Action class."
                    ),
                    why_it_matters=(
                        "Controllers should stay thin so they are easy to read, test, and evolve. "
                        "Business logic in controllers tends to get duplicated and makes refactors risky."
                    ),
                    suggested_fix=(
                        "Rule of thumb:\n"
                        "- If the operation is reusable, small, and used in more than one service: make it an Action.\n"
                        "- If it represents a full use-case/workflow: make it a Service.\n"
                        "\n"
                        "1. Extract the core logic to an `App\\Services\\...` Service or an `Action` class\n"
                        "2. Inject the service/action into the controller\n"
                        "3. Keep the controller method as orchestration (request -> call -> response)\n"
                        "4. Add unit tests for the extracted logic"
                    ),
                    tags=["architecture", "controllers", "services", "actions"],
                    confidence=confidence,
                )
            )

        return findings
