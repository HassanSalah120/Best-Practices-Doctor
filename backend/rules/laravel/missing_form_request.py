"""
Missing FormRequest Rule
Suggests using FormRequest when inline validation is detected in controllers.
"""
from schemas.facts import Facts, ValidationUsage
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


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
                    findings.append(self._create_finding(validation, rule_count))
        
        return findings
    
    def _create_finding(self, validation: ValidationUsage, rule_count: int) -> Finding:
        """Create a finding for missing FormRequest."""
        # Extract controller and method info from path
        method_name = validation.method_name or "unknown"
        
        # Generate FormRequest class name suggestion
        suggested_class = self._suggest_form_request_name(validation.file_path, method_name)
        
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
            ),
            code_example=self._generate_example(validation, suggested_class),
            tags=["validation", "form-request", "clean-code"],
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
