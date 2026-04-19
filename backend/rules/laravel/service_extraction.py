"""
Service Extraction Rule
Suggests extracting business logic from controllers to Service classes.
"""
import re

from schemas.facts import AssocArrayLiteral, Facts, MethodInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule
from core.project_recommendations import (
    enabled_capabilities,
    enabled_team_standards,
    project_aware_guidance,
    recommendation_context_tags,
)


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
    _READ_METHOD_NAMES = {"index", "show", "create", "edit", "results", "detail", "details", "view"}
    _DELEGATION_MARKERS = ("->execute(", "->handle(", "->process(", "->run(", "service->", "repository->", "coordinator->")
    _READ_RESPONSE_MARKERS = ("inertia::render(", "view(", "response()->", "json(", "return[")
    _QUERY_PRESENTER_RESOURCE_MARKERS = (
        "query->",
        "queries->",
        "presenter->",
        "presenters->",
        "resource::",
        "resourcecollection",
        "jsonresource::",
        "transformer->",
    )
    _MAPPING_CALL_MARKERS = ("->map(", "->transform(", "->sortby(", "->values(")
    _THIS_HELPER_CALL_PATTERN = re.compile(r"\$this->([a-zA-Z_][a-zA-Z0-9_]*)\(")
    
    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings = []
        
        min_business_loc = int(self.get_threshold("min_business_loc", 15))
        min_business_confidence = float(self.get_threshold("min_business_confidence", 0.6))
        loc_only_min_loc = int(self.get_threshold("loc_only_min_loc", 42))
        loc_only_min_call_sites = int(self.get_threshold("loc_only_min_call_sites", 5))
        enable_read_method_special_path = self._as_bool(
            self.get_threshold("enable_read_method_special_path", False),
            default=False,
        )
        read_payload_min_keys = int(self.get_threshold("read_payload_min_keys", 5) or 5)
        read_payload_min_array_literals = int(self.get_threshold("read_payload_min_array_literals", 2) or 2)
        serializer_helper_min_keys = int(self.get_threshold("serializer_helper_min_keys", 4) or 4)
        
        project_context = getattr(facts, "project_context", None)
        project_business_context = str(getattr(project_context, "project_business_context", "unknown") or "unknown")
        capabilities = enabled_capabilities(facts)
        team_standards = enabled_team_standards(facts)
        if "services_actions_expected" in team_standards:
            min_business_loc = max(12, int(min_business_loc) - 2)
        if project_business_context in {"saas_platform", "clinic_erp_management", "realtime_game_control_platform"}:
            min_business_loc = max(12, int(min_business_loc) - 1)

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
            serializer_helpers = self._controller_serializer_helpers(
                controller_methods,
                facts,
                min_keys=max(2, serializer_helper_min_keys),
            )
            
            for method in controller_methods:
                is_read_method = self._is_read_method(method)
                read_payload_mapping_signal = False
                serializer_helper_in_controller = False
                query_presenter_resource_delegated = False
                read_method_special_path = False
                if is_read_method and enable_read_method_special_path:
                    (
                        read_payload_mapping_signal,
                        serializer_helper_in_controller,
                        query_presenter_resource_delegated,
                    ) = self._analyze_read_method_payload(
                        method=method,
                        facts=facts,
                        serializer_helpers=serializer_helpers,
                        read_payload_min_keys=max(2, read_payload_min_keys),
                        read_payload_min_array_literals=max(1, read_payload_min_array_literals),
                    )
                    read_method_special_path = (
                        self._has_read_response_context(method)
                        and (read_payload_mapping_signal or serializer_helper_in_controller)
                        and not query_presenter_resource_delegated
                    )
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
                    project_business_context=project_business_context,
                    capabilities=capabilities,
                    team_standards=team_standards,
                    min_business_confidence=min_business_confidence,
                    loc_only_min_loc=loc_only_min_loc,
                    loc_only_min_call_sites=loc_only_min_call_sites,
                    is_read_method=is_read_method,
                    read_method_special_path=read_method_special_path,
                    read_payload_mapping_signal=read_payload_mapping_signal,
                    serializer_helper_in_controller=serializer_helper_in_controller,
                    query_presenter_resource_delegated=query_presenter_resource_delegated,
                )
                if decision_profile["suppression_checks"]["delegated"]:
                    continue
                if decision_profile["suppression_checks"]["layered_orchestration"]:
                    continue
                 
                # Skip if only dispatches jobs
                if decision_profile["suppression_checks"]["only_dispatches_jobs"]:
                    continue
                
                if is_read_method and not bool(decision_profile.get("read_method_special_path", False)):
                    continue

                should_emit = bool(decision_profile["emit"]) and (
                    bool(decision_profile.get("read_method_special_path", False))
                    or method.loc > min_business_loc
                )
                if should_emit:
                    findings.append(
                        self._create_finding(
                            controller,
                            method,
                            facts=facts,
                            decision_profile=decision_profile,
                            project_business_context=project_business_context,
                            capabilities=capabilities,
                            team_standards=team_standards,
                        )
                    )
        
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
        project_business_context: str = "unknown",
        capabilities: set[str] | None = None,
        team_standards: set[str] | None = None,
        min_business_confidence: float = 0.6,
        loc_only_min_loc: int = 42,
        loc_only_min_call_sites: int = 5,
        is_read_method: bool = False,
        read_method_special_path: bool = False,
        read_payload_mapping_signal: bool = False,
        serializer_helper_in_controller: bool = False,
        query_presenter_resource_delegated: bool = False,
    ) -> dict[str, object]:
        capabilities = set(capabilities or set())
        team_standards = set(team_standards or set())
        delegated = self._uses_action_or_service_delegation(method)
        layered_orchestration = self._looks_like_layered_orchestration(
            method,
            architecture_profile=architecture_profile,
            has_service_injection=has_service_injection,
            uses_repository_pattern=uses_repository_pattern,
        )
        only_dispatches_jobs = self._only_dispatches_jobs(method, facts)
        has_business_logic = self._detect_business_logic(
            method,
            metrics,
            min_business_confidence=min_business_confidence,
            loc_only_min_loc=loc_only_min_loc,
            loc_only_min_call_sites=loc_only_min_call_sites,
        )
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
        elif is_read_method:
            if read_method_special_path:
                decision = "emit"
            elif query_presenter_resource_delegated:
                decision = "skip"
                suppression_reason = "delegated-query-presenter-resource"
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
        if read_payload_mapping_signal:
            decision_reasons.append("read-payload-mapping-signal")
        if serializer_helper_in_controller:
            decision_reasons.append("serializer-helper-in-controller")
        if query_presenter_resource_delegated:
            decision_reasons.append("query-presenter-resource-delegated")
        if read_method_special_path:
            decision_reasons.append("read-method-special-path")

        return {
            "backend_framework": "laravel",
            "architecture_profile": architecture_profile,
            "profile_confidence": round(float(profile_confidence or 0.0), 2),
            "profile_confidence_kind": str(profile_confidence_kind or "unknown"),
            "profile_signals": list(profile_signals or [])[:8],
            "project_business_context": project_business_context,
            "capabilities": sorted(capabilities),
            "team_standards": sorted(team_standards),
            "service_injection": has_service_injection,
            "repository_pattern": uses_repository_pattern,
            "decision": decision,
            "decision_summary": (
                f"{decision} under {architecture_profile} profile"
                + (f" because {suppression_reason}" if suppression_reason else "")
                + (
                    " because read-method-payload-mapping"
                    if decision == "emit" and read_method_special_path
                    else ""
                )
                + (
                    " because business-logic-without-safe-orchestration"
                    if decision == "emit" and not read_method_special_path
                    else ""
                )
            ),
            "suppression_reason": suppression_reason,
            "decision_reasons": decision_reasons,
            "suppression_checks": {
                "delegated": delegated,
                "layered_orchestration": layered_orchestration,
                "only_dispatches_jobs": only_dispatches_jobs,
                "query_presenter_resource_delegated": query_presenter_resource_delegated,
            },
            "read_method_special_path": read_method_special_path,
            "read_payload_mapping_signal": read_payload_mapping_signal,
            "serializer_helper_in_controller": serializer_helper_in_controller,
            "emit": decision == "emit",
            "evidence_signals": [
                "framework=laravel",
                f"profile={architecture_profile}",
                f"profile_confidence={float(profile_confidence or 0.0):.2f}",
                f"profile_confidence_kind={profile_confidence_kind or 'unknown'}",
                f"business_context={project_business_context or 'unknown'}",
                f"capabilities={','.join(sorted(capabilities)) or 'none'}",
                f"team_standards={','.join(sorted(team_standards)) or 'none'}",
                f"service_injection={int(bool(has_service_injection))}",
                f"repository_pattern={int(bool(uses_repository_pattern))}",
                f"loc={method.loc or 0}",
                f"call_sites={len(method.call_sites or [])}",
                f"delegated={int(delegated)}",
                f"layered_orchestration={int(layered_orchestration)}",
                f"is_read_method={int(is_read_method)}",
                f"read_method_special_path={int(read_method_special_path)}",
                f"read_payload_mapping_signal={int(read_payload_mapping_signal)}",
                f"serializer_helper_in_controller={int(serializer_helper_in_controller)}",
                f"query_presenter_resource_delegated={int(query_presenter_resource_delegated)}",
                f"min_business_confidence={min_business_confidence:.2f}",
                f"loc_only_min_loc={int(loc_only_min_loc)}",
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
        has_dispatch = any(p in str(cs or "").lower() for cs in (method.call_sites or []) for p in dispatch_patterns)
        
        # If it has dispatches and minimal other logic, consider it thin
        if has_dispatch and method.loc < 10:
            return True
            
        return False

    def _is_read_method(self, method: MethodInfo) -> bool:
        return str(method.name or "").lower() in self._READ_METHOD_NAMES

    def _has_read_response_context(self, method: MethodInfo) -> bool:
        calls = [str(call or "").lower() for call in (method.call_sites or [])]
        return any(marker in call for call in calls for marker in self._READ_RESPONSE_MARKERS)

    def _is_query_presenter_resource_delegated(self, method: MethodInfo) -> bool:
        calls = [str(call or "").lower() for call in (method.call_sites or [])]
        return any(marker in call for call in calls for marker in self._QUERY_PRESENTER_RESOURCE_MARKERS)

    def _extract_this_helper_calls(self, method: MethodInfo) -> set[str]:
        helpers: set[str] = set()
        for call in (method.call_sites or []):
            text = str(call or "")
            for match in self._THIS_HELPER_CALL_PATTERN.findall(text):
                name = str(match or "").strip()
                if name:
                    helpers.add(name)
        return helpers

    def _method_assoc_arrays(self, facts: Facts, method: MethodInfo) -> list[AssocArrayLiteral]:
        out: list[AssocArrayLiteral] = []
        for arr in (facts.assoc_arrays or []):
            if arr.file_path != method.file_path:
                continue
            if str(arr.method_name or "") != str(method.name or ""):
                continue
            if method.class_fqcn and arr.class_fqcn and arr.class_fqcn != method.class_fqcn:
                continue
            out.append(arr)
        return out

    def _controller_serializer_helpers(
        self,
        controller_methods: list[MethodInfo],
        facts: Facts,
        *,
        min_keys: int,
    ) -> set[str]:
        helpers: set[str] = set()
        for method in controller_methods:
            if str(method.visibility or "public").lower() not in {"private", "protected"}:
                continue
            arrays = self._method_assoc_arrays(facts, method)
            if not arrays:
                continue
            max_keys = max((int(arr.key_count or 0) for arr in arrays), default=0)
            has_structured_return = any(
                int(arr.key_count or 0) >= min_keys and str(arr.used_as or "").lower() in {"return", "unknown", "argument"}
                for arr in arrays
            )
            has_any_return_shape = any(
                int(arr.key_count or 0) >= max(2, min_keys - 2) and str(arr.used_as or "").lower() in {"return", "unknown", "argument"}
                for arr in arrays
            )
            has_mapping_call = any(
                marker in str(call or "").lower()
                for call in (method.call_sites or [])
                for marker in self._MAPPING_CALL_MARKERS
            )
            has_serializer_name = any(
                token in str(method.name or "").lower()
                for token in ("serialize", "format", "payload", "viewdata", "present", "transform")
            )
            if has_structured_return and (has_mapping_call or has_serializer_name or max_keys >= min_keys + 1):
                helpers.add(str(method.name or ""))
                continue
            if has_serializer_name and has_any_return_shape and max_keys >= max(3, min_keys - 1):
                helpers.add(str(method.name or ""))
        return helpers

    def _analyze_read_method_payload(
        self,
        *,
        method: MethodInfo,
        facts: Facts,
        serializer_helpers: set[str],
        read_payload_min_keys: int,
        read_payload_min_array_literals: int,
    ) -> tuple[bool, bool, bool]:
        arrays = self._method_assoc_arrays(facts, method)
        if not arrays:
            helper_signal = bool(self._extract_this_helper_calls(method) & serializer_helpers)
            delegated = self._is_query_presenter_resource_delegated(method)
            return (False, helper_signal, delegated)

        max_keys = max((int(arr.key_count or 0) for arr in arrays), default=0)
        large_arrays = [arr for arr in arrays if int(arr.key_count or 0) >= read_payload_min_keys]
        nested_signal = any(
            int(arr.key_count or 0) >= read_payload_min_keys and str(arr.used_as or "").lower() in {"unknown", "argument"}
            for arr in arrays
        )
        has_mapping_call = any(
            marker in str(call or "").lower()
            for call in (method.call_sites or [])
            for marker in self._MAPPING_CALL_MARKERS
        )
        inline_payload_mapping_signal = bool(large_arrays) and (
            len(large_arrays) >= read_payload_min_array_literals
            or nested_signal
            or has_mapping_call
            or max_keys >= read_payload_min_keys + 2
        )
        helper_signal = bool(self._extract_this_helper_calls(method) & serializer_helpers)
        delegated = self._is_query_presenter_resource_delegated(method)
        return (inline_payload_mapping_signal, helper_signal, delegated)

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
        *,
        min_business_confidence: float,
        loc_only_min_loc: int,
        loc_only_min_call_sites: int,
    ) -> bool:
        """Detect if method contains business logic."""
        # Check metrics first
        if metrics:
            method_metrics = metrics.get(method.method_fqn)
            if method_metrics and method_metrics.has_business_logic:
                # If confidence wasn't computed (0.0), treat it as "unknown" and allow
                # the rule to decide using other gates (like method length).
                conf = getattr(method_metrics, "business_logic_confidence", 0.0)
                if conf == 0.0 or conf >= min_business_confidence:
                    return True
            if method_metrics:
                if (
                    method_metrics.cyclomatic_complexity >= 7
                    and (
                        method_metrics.query_count >= 2
                        or method_metrics.conditional_count >= 4
                        or method_metrics.loop_count >= 1
                    )
                ):
                    return True
        
        # Heuristic: check call sites for business logic patterns
        for call_site in method.call_sites:
            for pattern in self.BUSINESS_LOGIC_PATTERNS:
                if pattern in call_site.lower():
                    return True
        
        query_like_calls = sum(
            1
            for call_site in (method.call_sites or [])
            if any(
                token in call_site.lower()
                for token in ("->where", "->create", "->update", "->save", "->sync", "->attach", "->detach")
            )
        )
        if query_like_calls >= 2 and (method.loc or 0) >= max(25, int(loc_only_min_loc) - 10):
            return True

        # Last fallback: very long methods with many call sites still qualify.
        if (method.loc or 0) >= loc_only_min_loc and len(method.call_sites or []) >= loc_only_min_call_sites:
            return True
        
        return False
    
    def _create_finding(
        self,
        controller,
        method: MethodInfo,
        *,
        facts: Facts,
        decision_profile: dict[str, object],
        project_business_context: str,
        capabilities: set[str],
        team_standards: set[str],
    ) -> Finding:
        """Create service extraction finding."""
        base_name = controller.name.replace("Controller", "")
        service_name = f"{base_name}Service"
        confidence = 0.72
        if str(decision_profile.get("decision", "")) == "emit":
            confidence = max(confidence, 0.7 + min(0.22, (method.loc or 0) / 200))
        guidance = project_aware_guidance(facts, focus="service_boundaries")
        severity = self._calibrated_severity(project_business_context, capabilities, team_standards)
        read_method_special = bool(decision_profile.get("read_method_special_path", False))

        if read_method_special:
            title = "Extract read payload mapping from controller"
            description = (
                f"Read method `{method.name}` in `{controller.name}` performs payload mapping/serialization "
                "that should live in a Query/Presenter/Resource layer."
            )
            why_it_matters = (
                "Keeping read payload shaping inside controllers makes response contracts brittle and harder "
                "to reuse. Dedicated query/presenter/resource objects improve consistency and testability."
            )
            suggested_fix = (
                "1. Move payload mapping to a Query/Presenter/Resource class\n"
                "2. Keep controller method as orchestration (authorize/load -> delegate -> render)\n"
                "3. Reuse the same payload mapper in related read endpoints/tests"
            )
            code_example = (
                "// Before\n"
                "public function show(Request $request, Topic $topic)\n"
                "{\n"
                "    return Inertia::render('Admin/TopicShow', [\n"
                "        'topic' => $this->buildTopicViewData($topic),\n"
                "    ]);\n"
                "}\n\n"
                "// After\n"
                "public function show(Request $request, Topic $topic)\n"
                "{\n"
                "    return Inertia::render('Admin/TopicShow', [\n"
                "        'topic' => $this->topicAdminViewQuery->showTopic($topic),\n"
                "    ]);\n"
                "}\n"
            )
            tags = ["architecture", "service", "query", "presenter", "resource", *recommendation_context_tags(facts)]
        else:
            title = f"Extract business logic to {service_name}"
            description = (
                f"The `{method.name}` method in `{controller.name}` contains "
                f"{method.loc} lines of code with business logic. "
                f"Consider extracting to `App\\Services\\{service_name}`."
            )
            why_it_matters = (
                "Business logic in controllers cannot be reused by other parts of "
                "your application (CLI commands, queue jobs, other controllers). "
                "Services make logic testable, reusable, and keep controllers thin."
            )
            suggested_fix = (
                f"1. Create `app/Services/{service_name}.php`\n"
                f"2. Move business logic to a method like `{method.name}()`\n"
                f"3. Inject the service in your controller constructor\n"
                f"4. Call `$this->service->{method.name}()` from controller"
            )
            code_example = self._generate_example(controller.name, method.name, service_name)
            tags = ["architecture", "service", "refactor", *recommendation_context_tags(facts)]

        metadata: dict[str, object] = {"decision_profile": decision_profile}
        if read_method_special:
            metadata.update(
                {
                    "overlap_group": "controller-layering",
                    "overlap_scope": method.method_fqn,
                    "overlap_rank": 190,
                    "overlap_role": "child",
                }
            )

        return self.create_finding(
            title=title,
            file=method.file_path,
            line_start=method.line_start,
            line_end=method.line_end,
            description=description,
            why_it_matters=why_it_matters,
            suggested_fix=suggested_fix + (f"\n\nProject-aware guidance:\n{guidance}" if guidance else ""),
            code_example=code_example,
            tags=tags,
            severity=severity,
            confidence=confidence,
            evidence_signals=decision_profile.get("evidence_signals", []),
            metadata=metadata,
        )

    def _calibrated_severity(self, project_business_context: str, capabilities: set[str], team_standards: set[str]) -> Severity:
        if "services_actions_expected" in team_standards:
            return Severity.HIGH
        if project_business_context in {"saas_platform", "clinic_erp_management", "realtime_game_control_platform"}:
            return Severity.HIGH
        if {"billing", "realtime"} & set(capabilities):
            return Severity.HIGH
        return self.severity
    
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

    @staticmethod
    def _as_bool(value: object, *, default: bool = False) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return default
        text = str(value).strip().lower()
        if text in {"1", "true", "yes", "on"}:
            return True
        if text in {"0", "false", "no", "off"}:
            return False
        return default
