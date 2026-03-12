"""
Controller Inline Validation Rule

Flags inline validation inside controllers as a violation (suggest FormRequest).
"""
from schemas.facts import Facts, ValidationUsage
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class ControllerInlineValidationRule(Rule):
    """
    Detects `$request->validate(...)` or `Validator::make(...)` inside controllers.

    MissingFormRequestRule is advisory and keyed on rule-count; this rule is stricter and treats it as a violation.
    """

    id = "controller-inline-validation"
    name = "Inline Validation In Controller"
    description = "Detects inline validation inside controller actions (prefer FormRequest)"
    category = Category.VALIDATION
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

        controller_files = {c.file_path for c in facts.controllers}
        if not controller_files:
            return findings

        # Escalate to HIGH when validation rule-count is large.
        high_if_rules_ge = int(self.get_threshold("high_if_rules_ge", 6))

        grouped: dict[tuple[str, str], list[ValidationUsage]] = {}
        for v in facts.validations:
            if v.file_path not in controller_files:
                continue
            if v.validation_type == "form_request":
                continue
            grouped.setdefault((v.file_path, v.method_name), []).append(v)

        # Best-effort map file -> controller fqcn.
        fqcn_by_file: dict[str, str] = {}
        for c in facts.controllers:
            fqcn_by_file.setdefault(c.file_path, c.fqcn)

        for (file_path, method_name), vals in grouped.items():
            line_start = min(v.line_number for v in vals)
            max_rules = max((sum(len(r) for r in v.rules.values()) for v in vals), default=0)

            sev = self.severity
            if max_rules >= high_if_rules_ge:
                sev = Severity.HIGH

            controller_fqcn = fqcn_by_file.get(file_path, "")
            ctx = f"{controller_fqcn}::{method_name}" if controller_fqcn else f"{file_path}:{method_name}"

            examples = ", ".join(sorted({v.validation_type for v in vals})[:3])
            if len(vals) > 3:
                examples += f", +{len(vals) - 3} more"

            findings.append(
                self.create_finding(
                    title="Inline validation in controller (use FormRequest)",
                    context=ctx,
                    file=file_path,
                    line_start=line_start,
                    description=(
                        f"Detected inline validation inside a controller method ({examples}). "
                        "Prefer a dedicated FormRequest to keep controllers thin and validation reusable."
                        + (f" (Max rules detected: {max_rules}.)" if max_rules else "")
                    ),
                    why_it_matters=(
                        "Inline validation clutters controllers and makes validation rules hard to reuse or test. "
                        "FormRequests centralize rules and authorization, improving maintainability."
                    ),
                    suggested_fix=(
                        "1. Create a FormRequest: `php artisan make:request ...Request`\n"
                        "2. Move the rules into `rules()`\n"
                        "3. Type-hint the FormRequest in the controller method\n"
                        "4. Use `$request->validated()`"
                    ),
                    severity=sev,
                    tags=["validation", "form-request", "controllers"],
                )
            )

        return findings

