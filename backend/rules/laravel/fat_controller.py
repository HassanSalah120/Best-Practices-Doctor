"""
Fat Controller Detection Rule
Detects controllers that violate SRP by containing validation, queries, and business logic.
"""
from schemas.facts import Facts, MethodInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class FatControllerRule(Rule):
    """
    Detects "fat" controllers that do too much.
    
    A controller is fat if it contains:
    - Inline validation (should use FormRequest)
    - Database queries (should use Repository/Service)
    - Complex business logic (should use Service)
    """
    
    id = "fat-controller"
    name = "Fat Controller Detection"
    description = "Detects controllers with too many responsibilities"
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
        findings = []
        
        # Get thresholds
        max_method_loc = self.get_threshold("max_method_loc", self.get_threshold("max_loc", 30))
        max_queries = self.get_threshold("max_queries", 3)
        max_validations = self.get_threshold("max_validations", 0)
        max_methods = self.get_threshold("max_methods", None)
        
        # Analyze each controller
        for controller in facts.controllers:
            controller_issues = []
            
            # Skip if controller already delegates to services
            if self._delegates_to_services(controller, facts):
                continue
            
            # Get methods for this controller
            controller_methods = [
                m for m in facts.methods
                if (
                    (m.class_fqcn and m.class_fqcn == controller.fqcn)
                    or (m.file_path == controller.file_path and m.class_name == controller.name)
                )
            ]

            if isinstance(max_methods, int) and max_methods > 0:
                non_magic = [m for m in controller_methods if not m.name.startswith("__")]
                public_like = [m for m in non_magic if m.visibility == "public"]
                if len(public_like) > max_methods:
                    findings.append(self._create_controller_size_finding(
                        controller_name=controller.name,
                        file_path=controller.file_path,
                        line_start=controller.line_start,
                        line_end=controller.line_end,
                        method_count=len(public_like),
                        threshold=max_methods,
                    ))
            
            for method in controller_methods:
                issues = self._analyze_method(
                    method,
                    facts,
                    metrics,
                    max_method_loc,
                    max_queries,
                    max_validations,
                )
                controller_issues.extend(issues)
            
            # Create findings for significant issues
            for issue in controller_issues:
                findings.append(issue)
        
        return findings

    def _create_controller_size_finding(
        self,
        controller_name: str,
        file_path: str,
        line_start: int,
        line_end: int,
        method_count: int,
        threshold: int,
    ) -> Finding:
        return self.create_finding(
            title="Controller has too many public methods",
            context=controller_name,
            file=file_path,
            line_start=line_start,
            line_end=line_end,
            description=(
                f"Controller `{controller_name}` has {method_count} public methods "
                f"(threshold: {threshold}). This often indicates mixed responsibilities."
            ),
            why_it_matters=(
                "Controllers with many endpoints tend to accumulate unrelated concerns over time. "
                "Splitting by feature improves cohesion and testability."
            ),
            suggested_fix=(
                "Split this controller into multiple controllers organized by feature or resource.\n"
                "Keep each controller focused on a small, cohesive set of actions."
            ),
            tags=["srp", "architecture", "controller"],
        )
    
    def _delegates_to_services(self, controller, facts: Facts) -> bool:
        """Check if controller already delegates to services (thin controller)."""
        # Check constructor parameters for Service classes
        constructor = next(
            (m for m in facts.methods 
             if m.class_name == controller.name and m.name == "__construct"),
            None
        )
        
        if constructor:
            for param in constructor.parameters:
                if "Service" in param:
                    return True
        
        # Check if methods only call services (no direct DB queries)
        controller_methods = [
            m for m in facts.methods
            if (
                (m.class_fqcn and m.class_fqcn == controller.fqcn)
                or (m.file_path == controller.file_path and m.class_name == controller.name)
            )
        ]
        
        # If all public methods are short and call service-like methods, consider it thin
        public_methods = [m for m in controller_methods if not m.name.startswith("__") and m.visibility == "public"]
        if public_methods and all(m.loc <= 5 for m in public_methods):
            return True
        
        return False
    
    def _analyze_method(
        self,
        method: MethodInfo,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None,
        max_loc: int,
        max_queries: int,
        max_validations: int,
    ) -> list[Finding]:
        """Analyze a single controller method for fat controller symptoms."""
        import re

        findings = []
        problems = []
        
        # Skip magic methods and constructors
        if method.name.startswith("__"):
            return findings
        
        # Check method length
        if method.loc > max_loc:
            problems.append(f"Method has {method.loc} lines (max: {max_loc})")
        
        # Check for validation (prefer extracted facts; fallback to call-sites).
        # If the method already uses a FormRequest (typed param ending with *Request but not Request itself),
        # `$request->validated()` should not be counted as inline validation.
        has_form_request_param = False
        for p in method.parameters or []:
            s = str(p).strip()
            s = re.sub(r"^\\s*(?:public|protected|private)\\s+", "", s)
            s = re.sub(r"^\\s*readonly\\s+", "", s)
            parts = s.split()
            if len(parts) >= 2:
                t = parts[0].lstrip("?")
                base = t.split("\\\\")[-1]
                if base.endswith("Request") and base not in {"Request"}:
                    has_form_request_param = True
                    break

        validations_in_method = [
            v for v in facts.validations
            if v.file_path == method.file_path and method.line_start <= v.line_number <= (method.line_end or method.line_start)
        ]
        validation_calls = [
            cs for cs in method.call_sites
            if ("validate(" in cs.lower()) or ("validator::" in cs.lower())
        ]
        validation_count = 0 if has_form_request_param else max(len(validations_in_method), len(validation_calls))
        if validation_count > max_validations:
            problems.append(f"Contains {validation_count} validation call(s)")
        
        # Check for query patterns in call sites and extracted facts.
        queries_in_method = [
            q for q in facts.queries
            if q.file_path == method.file_path and method.line_start <= q.line_number <= (method.line_end or method.line_start)
        ]
        query_patterns = [
            "::where", "::find", "::all", "::get", "::first",
            "db::", "->get(", "->first(", "->paginate(", "->pluck(", "->count(", "->sum(", "->avg(", "->min(", "->max(",
        ]
        query_calls = [
            cs for cs in method.call_sites
            if any(p in cs.lower() for p in query_patterns)
        ]
        query_count = max(len(queries_in_method), len(query_calls))
        # Any DB access in a controller is a separation-of-concerns smell. Use `max_queries`
        # as a "how bad is it" threshold, not as a gate for detection.
        if query_count > 0:
            if query_count > max_queries:
                problems.append(f"Contains {query_count} database operations (max: {max_queries})")
            else:
                problems.append(f"Contains {query_count} database operation(s)")
        
        # Check metrics if available
        if metrics:
            method_metrics = metrics.get(method.method_fqn)
            if method_metrics:
                conf = getattr(method_metrics, "business_logic_confidence", 0.0)
                if method_metrics.has_business_logic and (conf == 0.0 or conf > 0.7):
                    problems.append("Contains business logic (should be in Service)")
        
        # If multiple problems, this is a fat controller method
        if len(problems) >= 2:
            findings.append(self.create_finding(
                title=f"Controller logic should be moved to service layers",
                context=f"{method.class_name}::{method.name}",
                file=method.file_path,
                line_start=method.line_start,
                line_end=method.line_end,
                description=f"The `{method.name}` method in `{method.class_name}` has multiple responsibilities:\n" +
                           "\n".join(f"- {p}" for p in problems),
                why_it_matters=(
                    "Fat controllers violate the Single Responsibility Principle. "
                    "They are harder to test, maintain, and reuse. "
                    "Business logic buried in controllers cannot be shared across "
                    "different entry points (CLI, API, jobs, etc.)."
                ),
                suggested_fix=self._generate_fix_suggestion(method, problems),
                code_example=self._generate_code_example(method),
                related_methods=[method.method_fqn],
                tags=["srp", "refactor", "architecture"],
            ))
        
        return findings
    
    def _generate_fix_suggestion(self, method: MethodInfo, problems: list[str]) -> str:
        """Generate specific fix suggestions based on detected problems."""
        suggestions = []
        
        for problem in problems:
            if "validation" in problem.lower():
                suggestions.append(
                    f"1. Create `App\\Http\\Requests\\{method.class_name.replace('Controller', '')}"
                    f"{method.name.title()}Request` for validation"
                )
            if "database" in problem.lower() or "queries" in problem.lower():
                suggestions.append(
                    f"2. Extract queries to a Repository or use a Service class"
                )
            if "business logic" in problem.lower():
                suggestions.append(
                    f"3. Create `App\\Services\\{method.class_name.replace('Controller', '')}Service` "
                    f"for business logic"
                )
            if "lines" in problem.lower():
                suggestions.append(
                    f"4. Break down the method into smaller, focused methods"
                )
        
        return "\n".join(suggestions) if suggestions else "Refactor to follow SRP"
    
    def _generate_code_example(self, method: MethodInfo) -> str:
        """Generate before/after code example."""
        controller_name = method.class_name
        method_name = method.name
        base_name = controller_name.replace("Controller", "")
        
        return f"""// Before (Fat Controller)
public function {method_name}(Request $request)
{{
    $validated = $request->validate([...]);
    // 50+ lines of logic, queries, etc.
}}

// After (Clean Controller)
public function {method_name}(
    {base_name}{method_name.title()}Request $request,
    {base_name}Service $service
) {{
    return $service->{method_name}($request->validated());
}}"""
