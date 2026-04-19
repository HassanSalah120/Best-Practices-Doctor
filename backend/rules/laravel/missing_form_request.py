"""
Missing FormRequest Rule
Suggests using FormRequest when inline validation is detected in controllers.
"""
from schemas.facts import Facts, ValidationUsage
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule
from core.project_recommendations import (
    enabled_capabilities,
    enabled_team_standards,
    project_aware_guidance,
    recommendation_context_tags,
)


class MissingFormRequestRule(Rule):
    """
    Detects inline validation in controllers and suggests FormRequest.
    
    FormRequests provide:
    - Reusable validation rules
    - Authorization logic in one place
    - Cleaner controllers
    - Better testability
    """
    
    id = "missing-form-request"
    name = "Missing FormRequest"
    description = "Suggests FormRequest for inline validation"
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
        findings = []
        
        # Backwards/forwards compatible threshold keys.
        # Older rulesets used `max_validator_rules` for this same "suggest if >= N rules" threshold.
        min_rules = self.get_threshold("min_rules", None)
        if min_rules is None:
            min_rules = self.get_threshold("max_validator_rules", 2)
        auth_flow_max_rules = int(self.get_threshold("auth_flow_max_rules_without_form_request", 3))

        project_context = getattr(facts, "project_context", None)
        architecture_style = str(getattr(project_context, "architecture_style", "") or "").strip().lower()
        if not architecture_style:
            architecture_style = str(getattr(project_context, "backend_architecture_profile", "unknown") or "unknown").lower()
        project_type = str(getattr(project_context, "project_type", "") or "").strip().lower()
        if not project_type:
            project_type = str(getattr(project_context, "project_business_context", "unknown") or "unknown").lower()
        capabilities = enabled_capabilities(facts)
        team_standards = enabled_team_standards(facts)

        if architecture_style == "mvc" and "form_requests_expected" not in team_standards:
            min_rules = max(int(min_rules), 3)
        if architecture_style == "api-first" or project_type == "api_backend":
            min_rules = max(1, int(min_rules) - 1)
        if "form_requests_expected" in team_standards:
            min_rules = max(1, int(min_rules) - 1)
            auth_flow_max_rules = max(1, auth_flow_max_rules - 1)
        
        # Group validations by file and method
        for validation in facts.validations:
            # Skip if already using FormRequest
            if validation.validation_type == "form_request":
                continue
            
            # Count validation rules
            rule_count = sum(len(rules) for rules in validation.rules.values())
            
            if rule_count >= min_rules:
                # Check if this is in a controller
                is_controller = any(
                    validation.file_path == c.file_path
                    for c in facts.controllers
                )
                
                if is_controller:
                    if self._is_auth_flow_validation(validation) and rule_count <= auth_flow_max_rules:
                        continue
                    findings.append(
                        self._create_finding(
                            validation,
                            rule_count,
                            facts=facts,
                            architecture_style=architecture_style,
                            project_type=project_type,
                            capabilities=capabilities,
                            team_standards=team_standards,
                        )
                    )
        
        return findings
    
    def _create_finding(
        self,
        validation: ValidationUsage,
        rule_count: int,
        *,
        facts: Facts,
        architecture_style: str,
        project_type: str,
        capabilities: set[str],
        team_standards: set[str],
    ) -> Finding:
        """Create a finding for missing FormRequest."""
        # Extract controller and method info from path
        method_name = validation.method_name or "unknown"
        
        # Generate FormRequest class name suggestion
        suggested_class = self._suggest_form_request_name(validation.file_path, method_name)
        guidance = project_aware_guidance(facts, focus="controller_boundaries")
        
        return self.create_finding(
            title=f"Use FormRequest instead of inline validation",
            context=method_name,
            file=validation.file_path,
            line_start=validation.line_number,
            description=(
                f"Found inline validation with {rule_count} rules. "
                f"Consider extracting to a FormRequest class for better organization."
            ),
            why_it_matters=(
                "Inline validation clutters controllers and cannot be reused. "
                "FormRequests centralize validation logic, provide authorization hooks, "
                "and make controllers cleaner. They're also easier to test independently."
            ),
            suggested_fix=(
                f"1. Create FormRequest: `php artisan make:request {suggested_class}`\n"
                f"2. Move validation rules to the `rules()` method\n"
                f"3. Add authorization logic to `authorize()` if needed\n"
                f"4. Type-hint the FormRequest in your controller method"
            ) + (f"\n\nProject-aware guidance:\n{guidance}" if guidance else ""),
            code_example=self._generate_example(validation, suggested_class),
            tags=["validation", "form-request", "clean-code", *recommendation_context_tags(facts)],
            metadata={
                "decision_profile": {
                    "decision": "emit",
                    "architecture_profile": architecture_style or "unknown",
                    "project_type": project_type or "unknown",
                    "project_business_context": project_type or "unknown",
                    "capabilities": sorted(capabilities),
                    "team_standards": sorted(team_standards),
                    "decision_summary": "Inline validation threshold exceeded for controller method under current project context.",
                    "decision_reasons": [
                        "controller-inline-validation",
                        f"rule_count={rule_count}",
                    ],
                    "recommendation_basis": [
                        "formrequest-improves-validation-boundaries",
                        "project-aware-guidance-applied" if guidance else "project-aware-guidance-none",
                    ],
                },
                "overlap_group": "controller-layering",
                "overlap_scope": f"{validation.file_path}:{method_name}",
                "overlap_rank": 110,
                "overlap_role": "child",
            },
        )
    
    def _suggest_form_request_name(self, file_path: str, method_name: str) -> str:
        """Generate a suggested FormRequest class name."""
        import re
        
        # Extract controller name from path
        match = re.search(r'(\w+)Controller\.php$', file_path)
        if match:
            base_name = match.group(1)
        else:
            base_name = "Item"
        
        # Map common method names to request names
        method_map = {
            "store": "Store",
            "update": "Update",
            "create": "Store",
            "edit": "Update",
            "destroy": "Delete",
        }
        
        action = method_map.get(method_name.lower(), method_name.title())
        
        return f"{action}{base_name}Request"

    def _is_auth_flow_validation(self, validation: ValidationUsage) -> bool:
        file_low = str(validation.file_path or "").lower().replace("\\", "/")
        method_low = str(validation.method_name or "").lower()
        if "/auth/" in file_low:
            return True
        return any(
            token in method_low
            for token in ("login", "register", "password", "reset", "verify", "twofactor", "two_factor", "forgot")
        )
    
    def _generate_example(self, validation: ValidationUsage, class_name: str) -> str:
        """Generate before/after code example."""
        # Format rules for example
        rules_str = "[\n"
        for field, rules in list(validation.rules.items())[:3]:
            joined_rules = "', '".join(rules)
            rules_str += f"            '{field}' => ['{joined_rules}'],\n"
        rules_str += "        ]"
        
        return f"""// Before (inline validation)
public function store(Request $request)
{{
    $validated = $request->validate({rules_str});
    // ...
}}

// After (FormRequest)
// In app/Http/Requests/{class_name}.php
class {class_name} extends FormRequest
{{
    public function authorize(): bool
    {{
        return true; // Add authorization logic
    }}

    public function rules(): array
    {{
        return {rules_str};
    }}
}}

// In controller
public function store({class_name} $request)
{{
    $validated = $request->validated();
    // ...
}}"""
