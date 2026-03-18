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
    _DELEGATION_MARKERS = ("->execute(", "->handle(", "->process(", "->run(", "service->", "repository->", "coordinator->")
    
    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings = []
        
        min_business_loc = self.get_threshold("min_business_loc", 15)
        
        project_context = getattr(facts, "project_context", None)
        architecture_profile = str(getattr(project_context, "backend_architecture_profile", "unknown") or "unknown").lower()
        if architecture_profile == "unknown":
            architecture_profile = "layered" if str(getattr(project_context, "backend_structure_mode", "unknown") or "unknown").lower() == "layered" else "unknown"
        profile_confidence = float(getattr(project_context, "backend_profile_confidence", 0.0) or 0.0)
        profile_confidence_kind = str(getattr(project_context, "backend_profile_confidence_kind", "unknown") or "unknown")
        profile_signals = list(getattr(project_context, "backend_profile_signals", []) or [])

        # Check each controller
        for controller in facts.controllers:
            has_service_injection = self._has_service_injection(controller, facts)
            uses_repository_pattern = self._uses_repository_pattern(controller, facts)
             
            controller_methods = [
                m for m in facts.methods
                if m.class_name == controller.name
            ]
            
            for method in controller_methods:
                # Skip simple CRUD methods
                if method.name in ["index", "show", "create", "edit"]:
                    continue
                decision_profile = self._decision_profile(
                    method,
                    facts=facts,
                    metrics=metrics,
                    architecture_profile=architecture_profile,
                    has_service_injection=has_service_injection,
                    uses_repository_pattern=uses_repository_pattern,
                    profile_confidence=profile_confidence,
                    profile_confidence_kind=profile_confidence_kind,
                    profile_signals=profile_signals,
                )
                if decision_profile["suppression_checks"]["delegated"]:
                    continue
                if decision_profile["suppression_checks"]["layered_orchestration"]:
                    continue
                 
                # Skip if only dispatches jobs
                if decision_profile["suppression_checks"]["only_dispatches_jobs"]:
                    continue
                
                if decision_profile["emit"] and method.loc > min_business_loc:
                    findings.append(self._create_finding(controller, method, decision_profile))
        
        return findings

    def _decision_profile(
        self,
        method: MethodInfo,
        *,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None,
        architecture_profile: str,
        has_service_injection: bool,
        uses_repository_pattern: bool,
        profile_confidence: float = 0.0,
        profile_confidence_kind: str = "unknown",
        profile_signals: list[str] | None = None,
    ) -> dict[str, object]:
        delegated = self._uses_action_or_service_delegation(method)
        layered_orchestration = self._looks_like_layered_orchestration(
            method,
            architecture_profile=architecture_profile,
            has_service_injection=has_service_injection,
            uses_repository_pattern=uses_repository_pattern,
        )
        only_dispatches_jobs = self._only_dispatches_jobs(method, facts)
        has_business_logic = self._detect_business_logic(method, metrics)
        decision = "skip"
        suppression_reason = None
        if delegated:
            decision = "suppress"
            suppression_reason = "delegated-to-action-or-service"
        elif layered_orchestration:
            decision = "suppress"
            suppression_reason = "thin-profile-orchestration"
        elif only_dispatches_jobs:
            decision = "suppress"
            suppression_reason = "job-dispatch-only"
        elif has_business_logic:
            decision = "emit"

        decision_reasons = []
        if has_business_logic:
            decision_reasons.append("business-logic-signal")
        if delegated:
            decision_reasons.append("delegated-to-action-or-service")
        if layered_orchestration:
            decision_reasons.append("thin-layered-orchestration")
        if only_dispatches_jobs:
            decision_reasons.append("job-dispatch-only")

        return {
            "backend_framework": "laravel",
            "architecture_profile": architecture_profile,
            "profile_confidence": round(float(profile_confidence or 0.0), 2),
            "profile_confidence_kind": str(profile_confidence_kind or "unknown"),
            "profile_signals": list(profile_signals or [])[:8],
            "service_injection": has_service_injection,
            "repository_pattern": uses_repository_pattern,
            "decision": decision,
            "decision_summary": (
                f"{decision} under {architecture_profile} profile"
                + (f" because {suppression_reason}" if suppression_reason else "")
                + (" because business-logic-without-safe-orchestration" if decision == "emit" else "")
            ),
            "suppression_reason": suppression_reason,
            "decision_reasons": decision_reasons,
            "suppression_checks": {
                "delegated": delegated,
                "layered_orchestration": layered_orchestration,
                "only_dispatches_jobs": only_dispatches_jobs,
            },
            "emit": has_business_logic and not delegated and not layered_orchestration and not only_dispatches_jobs,
            "evidence_signals": [
                "framework=laravel",
                f"profile={architecture_profile}",
                f"profile_confidence={float(profile_confidence or 0.0):.2f}",
                f"profile_confidence_kind={profile_confidence_kind or 'unknown'}",
                f"service_injection={int(bool(has_service_injection))}",
                f"repository_pattern={int(bool(uses_repository_pattern))}",
                f"loc={method.loc or 0}",
                f"call_sites={len(method.call_sites or [])}",
                f"delegated={int(delegated)}",
                f"layered_orchestration={int(layered_orchestration)}",
            ],
        }
    
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

    def _uses_action_or_service_delegation(self, method: MethodInfo) -> bool:
        params = [str(param or "") for param in (method.parameters or [])]
        has_action_param = any(
            any(token in param for token in ["Action", "Service", "Coordinator", "Workflow"])
            for param in params
        )
        has_execute_call = any(
            any(marker in str(call or "").lower() for marker in self._DELEGATION_MARKERS)
            for call in (method.call_sites or [])
        )
        return has_action_param and has_execute_call

    def _looks_like_layered_orchestration(
        self,
        method: MethodInfo,
        *,
        architecture_profile: str,
        has_service_injection: bool,
        uses_repository_pattern: bool,
    ) -> bool:
        layered_like = architecture_profile in {"layered", "modular"}
        api_first = architecture_profile == "api-first"
        mvc_profile = architecture_profile == "mvc"
        if not (layered_like or api_first or has_service_injection or uses_repository_pattern):
            return False

        call_sites = [str(call or "").lower() for call in (method.call_sites or [])]
        if not call_sites:
            return False

        delegation_calls = sum(
            1
            for call in call_sites
            if any(marker in call for marker in self._DELEGATION_MARKERS)
        )
        has_dto_or_request_mapping = any("dto" in call or "validated(" in call for call in call_sites)
        has_response = any(
            marker in call
            for call in call_sites
            for marker in ("return ", "redirect()->", "response()->", "back()->", "with(")
        )
        has_heavy_logic = any(
            marker in call
            for call in call_sites
            for marker in ("calculate", "compute", "transform", "merge", "rebalance", "rank", "assign", "reconcile")
        )

        return (
            (
                layered_like
                and delegation_calls >= 1
                and (method.loc or 0) <= 70
                and has_response
                and not has_heavy_logic
                and (has_dto_or_request_mapping or delegation_calls >= 2)
            )
            or (
                api_first
                and delegation_calls >= 1
                and (method.loc or 0) <= 75
                and has_response
                and not has_heavy_logic
                and any(marker in call for call in call_sites for marker in ("response()->", "json", "resource", "resourcecollection"))
            )
            or (
                mvc_profile
                and delegation_calls >= 1
                and (method.loc or 0) <= 55
                and has_response
                and not has_heavy_logic
                and not has_dto_or_request_mapping
            )
        )
    
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
    
    def _create_finding(self, controller, method: MethodInfo, decision_profile: dict[str, object]) -> Finding:
        """Create service extraction finding."""
        base_name = controller.name.replace("Controller", "")
        service_name = f"{base_name}Service"
        confidence = 0.72
        if str(decision_profile.get("decision", "")) == "emit":
            confidence = max(confidence, 0.7 + min(0.22, (method.loc or 0) / 200))
        
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
            confidence=confidence,
            evidence_signals=decision_profile.get("evidence_signals", []),
            metadata={"decision_profile": decision_profile},
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
