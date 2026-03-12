"""
Repository Suggestion Rule

Suggests extracting database logic to Repositories when controllers use Eloquent directly.
"""
from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class RepositorySuggestionRule(Rule):
    """
    Suggests using Repositories for database logic.
    
    Triggers when:
    - Controller methods use Eloquent directly (::where, ::find, etc)
    - Controller methods have high query counts
    """
    
    id = "repository-suggestion"
    name = "Repository Pattern Suggestion"
    description = "Suggests extracting database queries to Repository classes"
    category = Category.ARCHITECTURE
    default_severity = Severity.MEDIUM
    applicable_project_types = ["laravel_api", "laravel_blade", "laravel_inertia_react", "laravel_inertia_vue"]
    
    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings = []

        min_query_count = self.get_threshold("min_query_count", 2)
        min_complexity = self.get_threshold("min_complexity", 3)

        # Only analyze controllers (avoid namespace collisions by using file_path/FQCN).
        controller_files = {c.file_path for c in facts.controllers}
        controller_fqcn_by_file: dict[str, list[str]] = {}
        for c in facts.controllers:
            controller_fqcn_by_file.setdefault(c.file_path, []).append(c.fqcn)

        for method in facts.methods:
            if method.file_path not in controller_files:
                continue
            if method.class_fqcn:
                # If we know the method's class FQCN, ensure it matches a controller declared in the same file.
                # This prevents collisions when two controllers share the same short name in different namespaces.
                if method.class_fqcn not in set(controller_fqcn_by_file.get(method.file_path, [])):
                    continue
            
            # Skip if controller already uses service layer abstraction
            if self._has_service_layer_injection(method, facts):
                continue

            # Use metrics if available
            method_metrics = metrics.get(method.method_fqn) if metrics else None
            
            # Count queries (either from metrics or raw facts)
            if method_metrics:
                query_count = method_metrics.query_count
                has_business_logic = method_metrics.has_business_logic
                complexity = method_metrics.cyclomatic_complexity
            else:
                # Fallback to direct counting from call sites
                query_count = sum(1 for c in method.call_sites if "::where" in c or "::find" in c or "->get" in c)
                has_business_logic = query_count > 0
                complexity = 1
            
            # Check criteria
            if query_count >= min_query_count and complexity >= min_complexity:
                findings.append(self.create_finding(
                    title=f"Consider Repository Pattern for {method.method_fqn}",
                    file=method.file_path,
                    line_start=method.line_start,
                    line_end=method.line_end,
                    description=(
                        f"Method `{method.name}` contains {query_count} database queries "
                        f"and has a complexity of {complexity}. "
                        f"Direct Eloquent usage in controllers makes testing harder and duplicates logic."
                    ),
                    why_it_matters=(
                        "Repositories abstract data access, making the application easier to test, "
                        "maintain, and change. They strictly separate business logic from data access logic."
                    ),
                    suggested_fix=(
                        f"Extract queries to `{method.class_name.replace('Controller', '')}Repository` "
                        f"and inject it into the controller."
                    ),
                    code_example=self._generate_example(method.class_name),
                    tags=["architecture", "repository", "testing"],
                ))
        
        return findings
    
    def _generate_example(self, controller_name: str) -> str:
        """Generate before/after example."""
        model_name = controller_name.replace("Controller", "")
        repo_name = f"{model_name}Repository"
        variable_name = model_name.lower()
        
        return f"""// Before: Direct Eloquent in Controller
public function index()
{{
    $active = {model_name}::where('status', 'active')
        ->orderBy('created_at', 'desc')
        ->get();
    return view('index', compact('active'));
}}

// After: Using Repository
protected ${variable_name}Repo;

public function __construct({repo_name} ${variable_name}Repo)
{{
    $this->{variable_name}Repo = ${variable_name}Repo;
}}

public function index()
{{
    $active = $this->{variable_name}Repo->getActiveUsers();
    return view('index', compact('active'));
}}"""

    def _has_service_layer_injection(self, method, facts: Facts) -> bool:
        """Check if the controller already uses service layer abstraction (interface injection)."""
        # Find the constructor for this controller
        for m in facts.methods:
            if m.name != "__construct":
                continue
            if m.class_fqcn != method.class_fqcn and m.class_name != method.class_name:
                continue
            
            # Check constructor parameters for service interfaces
            for param in m.parameters or []:
                param_lower = param.lower()
                # Interface type hints indicate service layer pattern
                if "interface" in param_lower:
                    return True
                # Service injection patterns
                if "service" in param_lower and ("interface" in param_lower or param_lower.endswith("service")):
                    return True
            break
        
        # Check if method delegates to service layer via call sites
        call_sites_lower = " ".join(method.call_sites or []).lower()
        if "->" in call_sites_lower and "service->" in call_sites_lower:
            return True
        if "this->" in call_sites_lower and any(s in call_sites_lower for s in ["service->", "services->"]):
            return True
        
        return False
