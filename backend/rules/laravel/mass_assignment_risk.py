"""
Mass Assignment Risk Rule

Detects common mass-assignment anti-patterns like:
  Model::create($request->all())
  $model->update($request->all())

This is heuristic-based and uses AST-extracted call_sites (Tree-sitter primary).
"""
from schemas.facts import Facts, MethodInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class MassAssignmentRiskRule(Rule):
    id = "mass-assignment-risk"
    name = "Mass Assignment Risk"
    description = "Detects Model::create/update/fill with $request->all() (mass assignment risk)"
    category = Category.SECURITY
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

        risky_methods = ("create(", "update(", "fill(", "insert(")

        for m in facts.methods:
            hits: list[str] = []
            for c in m.call_sites or []:
                lc = c.lower()
                if "->all(" not in lc:
                    continue
                if "$request" not in lc and "request(" not in lc:
                    continue
                if not any(rm in lc for rm in risky_methods):
                    continue
                hits.append(c.strip())

            if not hits:
                continue

            sample = hits[0]
            if len(sample) > 140:
                sample = sample[:137] + "..."

            ctx = m.method_fqn
            findings.append(
                self.create_finding(
                    title="Potential mass assignment risk",
                    context=ctx,
                    file=m.file_path,
                    line_start=m.line_start,
                    line_end=m.line_end,
                    description=(
                        "Detected create/update/fill using `$request->all()` which can enable mass assignment of "
                        "unexpected attributes. "
                        f"Example: `{sample}`."
                    ),
                    why_it_matters=(
                        "Mass assignment vulnerabilities can allow attackers to set sensitive fields (e.g., `is_admin`) "
                        "if models are not properly guarded. Explicit whitelisting is safer and easier to review."
                    ),
                    suggested_fix=(
                        "1. Validate input and use `$request->validated()` (FormRequest)\n"
                        "2. Whitelist fields: `$request->only(['field1', 'field2'])`\n"
                        "3. Ensure models define `$fillable` (or use `$guarded = []` only with care)\n"
                        "4. Consider DTOs to make allowed fields explicit"
                    ),
                    tags=["security", "mass-assignment", "laravel", "validation"],
                    confidence=0.7,
                )
            )

        return findings

