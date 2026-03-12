"""
Service Extraction Rule
Suggests extracting business logic from controllers to Service classes.
"""
from schemas.facts import Facts, MethodInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class ServiceExtractionRule(Rule):
    """
    Detects business logic in controllers that should be in Services.
    
    Services provide:
    - Reusable business logic across controllers, jobs, commands
    - Better testability (unit test logic without HTTP)
    - Clear separation of concerns
    """
    
    id = "service-extraction"
    name = "Service Extraction Suggestion"
    description = "Suggests extracting business logic to Service classes"
    category = Category.ARCHITECTURE
    default_severity = Severity.MEDIUM
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]
    
    # Patterns that indicate business logic (not just CRUD)
    BUSINESS_LOGIC_PATTERNS = [
        "calculate", "compute", "process", "transform", "convert",
        "generate", "build", "parse", "validate", "verify",
        "sync", "import", "export", "notify", "send",
        "charge", "refund", "subscribe", "cancel",
    ]
    
    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings = []
        
        min_business_loc = self.get_threshold("min_business_loc", 15)
        
        # Check each controller
        for controller in facts.controllers:
            # Skip if already has service injection
            if self._has_service_injection(controller, facts):
                continue
            
            # Skip if already uses repository pattern (thin controller)
            if self._uses_repository_pattern(controller, facts):
                continue
            
            controller_methods = [
                m for m in facts.methods
                if m.class_name == controller.name
            ]
            
            for method in controller_methods:
                # Skip simple CRUD methods
                if method.name in ["index", "show", "create", "edit"]:
                    continue
                
                # Skip if only dispatches jobs
                if self._only_dispatches_jobs(method, facts):
                    continue
                
                # Check for business logic indicators
                has_business_logic = self._detect_business_logic(method, metrics)
                
                if has_business_logic and method.loc > min_business_loc:
                    findings.append(self._create_finding(controller, method))
        
        return findings
    
    def _has_service_injection(self, controller, facts: Facts) -> bool:
        """Check if controller already uses service injection."""
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
        
        return False
    
    def _uses_repository_pattern(self, controller, facts: Facts) -> bool:
        """Check if controller uses repository pattern (thin controller)."""
        # Check for Repository injection in constructor
        constructor = next(
            (m for m in facts.methods 
             if m.class_name == controller.name and m.name == "__construct"),
            None
        )
        
        if constructor:
            for param in constructor.parameters:
                if "Repository" in param:
                    return True
        
        return False
    
    def _only_dispatches_jobs(self, method: MethodInfo, facts: Facts) -> bool:
        """Check if method only dispatches jobs (not business logic)."""
        # If method only calls dispatch, job dispatch, or simple redirects, it's thin
        dispatch_patterns = ["dispatch", "dispatchSync", "dispatchNow", "bus::"]
        has_dispatch = any(p in cs.lower() for cs in method.call_sites for p in dispatch_patterns)
        
        # If it has dispatches and minimal other logic, consider it thin
        if has_dispatch and method.loc < 10:
            return True
            
        return False
    
    def _detect_business_logic(
        self,
        method: MethodInfo,
        metrics: dict[str, MethodMetrics] | None,
    ) -> bool:
        """Detect if method contains business logic."""
        # Check metrics first
        if metrics:
            method_metrics = metrics.get(method.method_fqn)
            if method_metrics and method_metrics.has_business_logic:
                # If confidence wasn't computed (0.0), treat it as "unknown" and allow
                # the rule to decide using other gates (like method length).
                conf = getattr(method_metrics, "business_logic_confidence", 0.0)
                return conf == 0.0 or conf > 0.5
        
        # Heuristic: check call sites for business logic patterns
        for call_site in method.call_sites:
            for pattern in self.BUSINESS_LOGIC_PATTERNS:
                if pattern in call_site.lower():
                    return True
        
        # Heuristic: complex methods likely have business logic
        if method.loc > 20:
            return True
        
        return False
    
    def _create_finding(self, controller, method: MethodInfo) -> Finding:
        """Create service extraction finding."""
        base_name = controller.name.replace("Controller", "")
        service_name = f"{base_name}Service"
        
        return self.create_finding(
            title=f"Extract business logic to {service_name}",
            file=method.file_path,
            line_start=method.line_start,
            line_end=method.line_end,
            description=(
                f"The `{method.name}` method in `{controller.name}` contains "
                f"{method.loc} lines of code with business logic. "
                f"Consider extracting to `App\\Services\\{service_name}`."
            ),
            why_it_matters=(
                "Business logic in controllers cannot be reused by other parts of "
                "your application (CLI commands, queue jobs, other controllers). "
                "Services make logic testable, reusable, and keep controllers thin."
            ),
            suggested_fix=(
                f"1. Create `app/Services/{service_name}.php`\n"
                f"2. Move business logic to a method like `{method.name}()`\n"
                f"3. Inject the service in your controller constructor\n"
                f"4. Call `$this->service->{method.name}()` from controller"
            ),
            code_example=self._generate_example(controller.name, method.name, service_name),
            tags=["architecture", "service", "refactor"],
        )
    
    def _generate_example(self, controller_name: str, method_name: str, service_name: str) -> str:
        """Generate before/after code example."""
        return f"""// Before (logic in controller)
class {controller_name} extends Controller
{{
    public function {method_name}(Request $request)
    {{
        // 30+ lines of business logic
        $result = $this->complexCalculation($request->data);
        $this->processResult($result);
        // ...
    }}
}}

// After (logic in service)
// app/Services/{service_name}.php
class {service_name}
{{
    public function {method_name}(array $data): Result
    {{
        $result = $this->complexCalculation($data);
        $this->processResult($result);
        return $result;
    }}
}}

// Controller (thin)
class {controller_name} extends Controller
{{
    public function __construct(
        private {service_name} $service
    ) {{}}

    public function {method_name}(FormRequest $request)
    {{
        $result = $this->service->{method_name}($request->validated());
        return response()->json($result);
    }}
}}"""
