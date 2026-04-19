"""
Repository Suggestion Rule

Suggests extracting database logic to Repositories when controllers use Eloquent directly.
"""
from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule
from core.project_recommendations import (
    enabled_capabilities,
    enabled_team_standards,
    project_aware_guidance,
    recommendation_context_tags,
)


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
    _WRITE_QUERY_TOKENS = ("create", "insert", "update", "upsert", "delete", "save", "sync", "attach", "detach")
    _RESTFUL_READ_METHODS = {"index", "show", "list", "search", "create", "edit"}
    
    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings = []

        min_query_count = int(self.get_threshold("min_query_count", 2))
        min_complexity = int(self.get_threshold("min_complexity", 3))
        min_write_queries = int(self.get_threshold("min_write_queries", 0))
        read_only_blocked_max_queries = int(self.get_threshold("read_only_blocked_max_queries", 2))

        project_context = getattr(facts, "project_context", None)
        architecture_style = str(getattr(project_context, "architecture_style", "") or "").strip().lower()
        if not architecture_style:
            architecture_style = str(getattr(project_context, "backend_architecture_profile", "unknown") or "unknown").lower()
        project_type = str(getattr(project_context, "project_type", "") or "").strip().lower()
        if not project_type:
            project_type = str(getattr(project_context, "project_business_context", "unknown") or "unknown").lower()
        capabilities = enabled_capabilities(facts)
        team_standards = enabled_team_standards(facts)
        repositories_expected = "repositories_expected" in team_standards

        if architecture_style == "mvc" and not repositories_expected:
            min_query_count = max(int(min_query_count), 3)
            min_complexity = max(int(min_complexity), 4)
            min_write_queries = max(int(min_write_queries), 1)

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
            method_queries = [q for q in facts.queries if q.file_path == method.file_path and q.method_name == method.name]
            
            # Count queries (either from metrics or raw facts)
            if method_metrics:
                query_count = method_metrics.query_count
                complexity = method_metrics.cyclomatic_complexity
            else:
                # Fallback to direct counting from call sites
                query_count = sum(1 for c in (method.call_sites or []) if "::where" in c or "::find" in c or "->get" in c)
                complexity = 1

            write_query_count = sum(
                1
                for query in method_queries
                if str(getattr(query, "query_type", "") or "").strip().lower() in {"insert", "update", "delete", "upsert"}
                or any(token in str(getattr(query, "method_chain", "") or "").lower() for token in self._WRITE_QUERY_TOKENS)
            )
            read_only_route_like = (
                method.name.lower() in self._RESTFUL_READ_METHODS
                and write_query_count == 0
                and query_count <= read_only_blocked_max_queries
            )
            if read_only_route_like and architecture_style in {"mvc", "unknown"} and not repositories_expected:
                continue
            if self._is_orchestrated_read_method(method) and write_query_count == 0 and query_count <= max(2, min_query_count):
                continue
            if min_write_queries > 0 and write_query_count < min_write_queries:
                continue
            
            # Check criteria
            if query_count >= min_query_count and complexity >= min_complexity:
                guidance = project_aware_guidance(facts, focus="service_boundaries")
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
                    ) + (f"\n\nProject-aware guidance:\n{guidance}" if guidance else ""),
                    severity=self._calibrated_severity(architecture_style, project_type, capabilities, team_standards),
                    code_example=self._generate_example(method.class_name),
                    tags=["architecture", "repository", "testing", *recommendation_context_tags(facts)],
                    metadata={
                        "decision_profile": {
                            "decision": "emit",
                            "architecture_profile": architecture_style or "unknown",
                            "project_type": project_type or "unknown",
                            "project_business_context": project_type or "unknown",
                            "capabilities": sorted(capabilities),
                            "team_standards": sorted(team_standards),
                            "decision_summary": (
                                f"Controller query density crossed repository threshold under {architecture_style or 'unknown'} context."
                            ),
                            "decision_reasons": [
                                f"query_count={query_count}",
                                f"complexity={complexity}",
                                f"write_query_count={write_query_count}",
                                f"repositories_expected={int(repositories_expected)}",
                            ],
                            "recommendation_basis": [
                                "repository-boundary-improves-query-separation",
                                "project-aware-guidance-applied" if guidance else "project-aware-guidance-none",
                            ],
                        },
                        "overlap_group": "controller-layering",
                        "overlap_scope": method.method_fqn,
                        "overlap_rank": 140,
                        "overlap_role": "child",
                    },
                ))
        
        return findings

    def _calibrated_severity(
        self,
        architecture_style: str,
        project_type: str,
        capabilities: set[str],
        team_standards: set[str],
    ) -> Severity:
        if "repositories_expected" in team_standards:
            return Severity.MEDIUM
        if architecture_style in {"layered", "modular"}:
            return Severity.MEDIUM
        if architecture_style == "mvc":
            return Severity.LOW
        if project_type in {"saas_platform", "clinic_erp_management"}:
            return Severity.MEDIUM
        if "multi_tenant" in capabilities:
            return Severity.MEDIUM
        return self.severity
    
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

    def _is_orchestrated_read_method(self, method) -> bool:
        method_name = str(getattr(method, "name", "") or "").lower()
        if method_name not in self._RESTFUL_READ_METHODS:
            return False
        call_sites = [str(call or "").lower() for call in (getattr(method, "call_sites", []) or [])]
        if not call_sites:
            return False
        has_delegation = any(
            marker in call for call in call_sites for marker in ("->execute(", "->handle(", "service->", "repository->", "queryservice->")
        )
        if not has_delegation:
            return False
        has_response = any(marker in call for call in call_sites for marker in ("return ", "response()->", "inertia::render", "view("))
        return has_response
