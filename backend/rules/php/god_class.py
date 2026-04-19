"""
God Class Rule
Flags classes that are too large (many lines and/or many methods).
"""
from schemas.facts import Facts, ClassInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule
from core.project_recommendations import (
    enabled_capabilities,
    enabled_team_standards,
    project_aware_guidance,
    project_business_context,
    recommendation_context_tags,
)


class GodClassRule(Rule):
    """
    Detects "god classes" (low cohesion, too many responsibilities).

    Heuristics:
    - Large LOC (class size)
    - Large public-ish method count
    """

    _COORDINATOR_NAME_MARKERS = (
        "coordinator",
        "orchestrator",
        "workflow",
        "server",
        "manager",
        "handler",
        "gateway",
        "dispatcher",
        "broker",
        "router",
    )
    _SERVICE_PARAM_MARKERS = (
        "service",
        "handler",
        "manager",
        "gateway",
        "dispatcher",
        "broker",
        "publisher",
        "interface",
        "queue",
        "token",
        "command",
        "connection",
        "circuitbreaker",
        "visibility",
        "repository",
        "validator",
        "transport",
        "store",
    )
    _BOUNDED_FACADE_DEP_MARKERS = (
        "coordinator",
        "orchestrator",
        "workflow",
        "facade",
    )
    _DELEGATION_CALL_MARKERS = (
        "->execute(",
        "->handle(",
        "->run(",
        "service->",
        "services->",
        "operations->",
        "action->",
        "actions->",
        "coordinator->",
        "workflow->",
        "repository->",
        "repositories->",
        "gateway->",
    )
    _DISPATCH_METHOD_NAMES = ("dispatch", "route", "execute", "handle")
    _INTERFACE_FACADE_METHOD_LIMIT = 40

    id = "god-class"
    name = "God Class Detection"
    description = "Flags classes that are too large and likely violate SRP/cohesion"
    category = Category.MAINTAINABILITY
    default_severity = Severity.HIGH

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        max_loc = self.get_threshold("max_loc", self.get_threshold("max_lines", 300))
        max_methods = self.get_threshold("max_methods", 20)
        project_context = getattr(facts, "project_context", None)
        business_context = project_business_context(facts)
        capabilities = enabled_capabilities(facts)
        team_standards = enabled_team_standards(facts)
        architecture_profile = str(getattr(project_context, "backend_architecture_profile", "unknown") or "unknown").lower()
        if architecture_profile == "unknown":
            architecture_profile = "layered" if str(getattr(project_context, "backend_structure_mode", "unknown") or "unknown").lower() == "layered" else "unknown"
        profile_confidence = float(getattr(project_context, "backend_profile_confidence", 0.0) or 0.0)
        profile_confidence_kind = str(getattr(project_context, "backend_profile_confidence_kind", "unknown") or "unknown")
        profile_signals = list(getattr(project_context, "backend_profile_signals", []) or [])

        for cls in facts.classes:
            # Skip framework/vendor classes that might slip through.
            if not cls.file_path or "vendor" in cls.file_path.replace("\\", "/"):
                continue

            loc = 0
            if cls.line_end and cls.line_start and cls.line_end >= cls.line_start:
                loc = cls.line_end - cls.line_start + 1

            methods = []
            all_class_methods = []
            for m in facts.methods:
                # Prefer FQCN match when available to avoid mixing namespaces.
                if m.class_fqcn and cls.fqcn and m.class_fqcn == cls.fqcn:
                    all_class_methods.append(m)
                    if m.name.startswith("__"):
                        continue
                    methods.append(m)
                    continue
                # Fallback: file + class name match (still disambiguates duplicates across namespaces).
                if m.file_path == cls.file_path and m.class_name == cls.name:
                    all_class_methods.append(m)
                    if m.name.startswith("__"):
                        continue
                    methods.append(m)
            public_like = [m for m in methods if (m.visibility or "public") == "public"]

            # Trigger on either dimension; give richer description if both are exceeded.
            too_large = loc > max_loc if max_loc else False
            too_many = len(public_like) > max_methods if max_methods else False
            if not (too_large or too_many):
                continue

            coordinator_shape = self._is_service_coordinator(cls, public_like, all_class_methods, architecture_profile)
            bounded_service_facade = self._is_bounded_service_facade(
                cls,
                public_like,
                all_class_methods,
                architecture_profile,
            )
            command_dispatch_facade = self._is_command_dispatch_facade(
                cls,
                public_like,
                all_class_methods,
                architecture_profile,
            )
            interface_service_facade = self._is_interface_service_facade(
                cls,
                public_like,
                all_class_methods,
                architecture_profile,
            )
            if coordinator_shape or bounded_service_facade or command_dispatch_facade or interface_service_facade:
                continue
            guidance = project_aware_guidance(facts, focus="orchestration_boundaries")
            severity = self._calibrated_severity(business_context, capabilities, team_standards)

            reasons: list[str] = []
            if too_large:
                reasons.append(f"class is {loc} LOC (threshold: {max_loc})")
            if too_many:
                reasons.append(f"class has {len(public_like)} public methods (threshold: {max_methods})")

            findings.append(
                self.create_finding(
                    title="Class is too large (god class)",
                    context=cls.fqcn or cls.name,
                    file=cls.file_path,
                    line_start=cls.line_start or 1,
                    line_end=cls.line_end or None,
                    description=(
                        f"Class `{cls.name}` looks like a god class: " + ", ".join(reasons) + ". "
                        "This often indicates mixed responsibilities and low cohesion."
                    ),
                    why_it_matters=(
                        "God classes accumulate unrelated behavior, become difficult to test, and make changes risky. "
                        "Breaking them up improves cohesion, reduces coupling, and makes the codebase easier to evolve."
                    ),
                    suggested_fix=(
                        "1. Identify distinct responsibilities within the class\n"
                        "2. Extract cohesive behavior into smaller classes (Services, Actions, Value Objects)\n"
                        "3. Prefer composition over inheritance\n"
                        "4. Add tests around the extracted seams"
                    ) + (f"\n\nProject-aware guidance:\n{guidance}" if guidance else ""),
                    tags=["srp", "cohesion", "maintainability", "refactor", *recommendation_context_tags(facts)],
                    severity=severity,
                    confidence=min(0.95, 0.62 + (0.14 if too_large else 0.0) + (0.14 if too_many else 0.0)),
                    evidence_signals=[
                        f"profile={architecture_profile}",
                        f"profile_confidence={profile_confidence:.2f}",
                        f"profile_confidence_kind={profile_confidence_kind}",
                        f"business_context={business_context or 'unknown'}",
                        f"capabilities={','.join(sorted(capabilities)) or 'none'}",
                        f"team_standards={','.join(sorted(team_standards)) or 'none'}",
                        f"loc={loc}",
                        f"public_methods={len(public_like)}",
                        f"coordinator_shape={int(coordinator_shape)}",
                        f"bounded_service_facade={int(bounded_service_facade)}",
                        f"command_dispatch_facade={int(command_dispatch_facade)}",
                        f"interface_service_facade={int(interface_service_facade)}",
                    ],
                    metadata={
                        "decision_profile": {
                            "backend_framework": "laravel" if architecture_profile != "unknown" else "unknown",
                            "architecture_profile": architecture_profile,
                            "profile_confidence": round(profile_confidence, 2),
                            "profile_confidence_kind": profile_confidence_kind,
                            "profile_signals": profile_signals[:8],
                            "project_business_context": business_context,
                            "capabilities": sorted(capabilities),
                            "team_standards": sorted(team_standards),
                            "loc": loc,
                            "public_methods": len(public_like),
                            "coordinator_shape": coordinator_shape,
                            "bounded_service_facade": bounded_service_facade,
                            "command_dispatch_facade": command_dispatch_facade,
                            "interface_service_facade": interface_service_facade,
                            "too_large": too_large,
                            "too_many_methods": too_many,
                            "decision": "emit",
                            "decision_summary": "emit because class exceeds size thresholds without bounded coordinator suppression",
                        }
                    },
                )
            )

        return findings

    def _calibrated_severity(self, business_context: str, capabilities: set[str], team_standards: set[str]) -> Severity:
        if business_context in {"realtime_game_control_platform", "saas_platform", "clinic_erp_management"}:
            return Severity.HIGH
        if {"realtime", "queue_heavy"} & set(capabilities):
            return Severity.HIGH
        if "services_actions_expected" in team_standards:
            return Severity.HIGH
        return self.severity

    def _is_service_coordinator(self, cls: ClassInfo, public_like: list, methods: list, architecture_profile: str) -> bool:
        path = str(cls.file_path or "").replace("\\", "/").lower()
        name = str(cls.name or "").lower()
        layered_like = architecture_profile in {"layered", "modular"}
        has_coordinator_name = any(marker in name for marker in self._COORDINATOR_NAME_MARKERS)
        has_coordinator_path = any(marker in path for marker in ("/workflow/", "/workflows/", "/coordination/", "/orchestrators/", "/servers/"))
        has_layered_server = layered_like and "/services/" in path and "server" in name
        if not (has_coordinator_name or has_coordinator_path or has_layered_server):
            return False

        constructor = next((m for m in methods if m.name == "__construct"), None)
        if constructor is None:
            return False

        params = [str(param or "").lower() for param in (constructor.parameters or [])]
        if len(params) < 5:
            return False

        service_like = sum(
            1 for param in params if any(marker in param for marker in self._SERVICE_PARAM_MARKERS)
        )
        if service_like < max(4, len(params) - 1):
            return False

        if architecture_profile == "mvc" and not any(marker in name for marker in ("coordinator", "orchestrator", "workflow")):
            return False

        if len(public_like) > (16 if layered_like else 14):
            return False

        avg_public_loc = (
            sum((m.loc or max(0, (m.line_end or 0) - (m.line_start or 0) + 1)) for m in public_like) / len(public_like)
            if public_like else 0
        )
        return avg_public_loc <= (55 if layered_like else 45)

    def _is_bounded_service_facade(
        self,
        cls: ClassInfo,
        public_like: list,
        methods: list,
        architecture_profile: str,
    ) -> bool:
        path = str(cls.file_path or "").replace("\\", "/").lower()
        name = str(cls.name or "").lower()
        if "/services/" not in path or not name.endswith("service"):
            return False
        if architecture_profile not in {"layered", "modular", "unknown"}:
            return False

        constructor = next((m for m in methods if m.name == "__construct"), None)
        if constructor is None:
            return False

        params = [str(param or "").lower() for param in (constructor.parameters or [])]
        dep_count = len(params)
        if dep_count < 5 or dep_count > 7:
            return False

        service_like = sum(
            1 for param in params if any(marker in param for marker in self._SERVICE_PARAM_MARKERS)
        )
        facade_like = sum(
            1 for param in params if any(marker in param for marker in self._BOUNDED_FACADE_DEP_MARKERS)
        )
        if service_like < max(4, dep_count - 1) or facade_like < 1:
            return False

        public_methods = [m for m in public_like if not str(m.name or "").startswith("__")]
        if not public_methods or len(public_methods) > 14:
            return False

        delegated = 0
        for method in public_methods:
            call_sites = [str(call or "").lower() for call in (method.call_sites or [])]
            if any(any(marker in call for marker in self._DELEGATION_CALL_MARKERS) for call in call_sites):
                delegated += 1

        delegation_ratio = delegated / len(public_methods)
        if delegation_ratio < 0.4:
            return False

        avg_public_loc = (
            sum((m.loc or max(0, (m.line_end or 0) - (m.line_start or 0) + 1)) for m in public_methods)
            / len(public_methods)
        )
        return avg_public_loc <= 60

    def _is_interface_service_facade(
        self,
        cls: ClassInfo,
        public_like: list,
        methods: list,
        architecture_profile: str,
    ) -> bool:
        path = str(cls.file_path or "").replace("\\", "/").lower()
        name = str(cls.name or "").lower()
        if "/services/" not in path or not name.endswith("service"):
            return False
        if architecture_profile not in {"layered", "modular", "unknown"}:
            return False

        implemented_contracts = [str(contract or "").lower() for contract in (cls.implements or [])]
        if not any(contract.endswith("interface") for contract in implemented_contracts):
            return False

        public_methods = [m for m in public_like if not str(m.name or "").startswith("__")]
        if not public_methods or len(public_methods) > self._INTERFACE_FACADE_METHOD_LIMIT:
            return False

        constructor = next((m for m in methods if m.name == "__construct"), None)
        if constructor is None:
            return False

        params = [str(param or "").lower() for param in (constructor.parameters or [])]
        service_like = sum(
            1 for param in params if any(marker in param for marker in self._SERVICE_PARAM_MARKERS)
        )
        if not params or service_like < max(1, len(params) // 2):
            return False

        delegated = 0
        for method in public_methods:
            call_sites = [str(call or "").lower() for call in (method.call_sites or [])]
            if any(any(marker in call for marker in self._DELEGATION_CALL_MARKERS) for call in call_sites):
                delegated += 1

        delegation_ratio = delegated / len(public_methods)
        if delegation_ratio < 0.75:
            return False

        avg_public_loc = (
            sum((m.loc or max(0, (m.line_end or 0) - (m.line_start or 0) + 1)) for m in public_methods)
            / len(public_methods)
        )
        return avg_public_loc <= 14

    def _is_command_dispatch_facade(
        self,
        cls: ClassInfo,
        public_like: list,
        methods: list,
        architecture_profile: str,
    ) -> bool:
        path = str(cls.file_path or "").replace("\\", "/").lower()
        name = str(cls.name or "").lower()
        if "/services/" not in path or not name.endswith("service"):
            return False
        if architecture_profile not in {"layered", "modular", "unknown"}:
            return False

        constructor = next((m for m in methods if m.name == "__construct"), None)
        if constructor is None:
            return False

        params = [str(param or "").lower() for param in (constructor.parameters or [])]
        dep_count = len(params)
        if dep_count < 5 or dep_count > 8:
            return False

        service_like = sum(
            1 for param in params if any(marker in param for marker in self._SERVICE_PARAM_MARKERS)
        )
        facade_like = sum(
            1 for param in params if any(marker in param for marker in self._BOUNDED_FACADE_DEP_MARKERS)
        )
        if service_like < max(4, dep_count - 1) or facade_like < 1:
            return False

        public_methods = [m for m in public_like if not str(m.name or "").startswith("__")]
        if not public_methods or len(public_methods) > 4:
            return False

        dispatch_method = next(
            (m for m in public_methods if str(m.name or "").lower() in self._DISPATCH_METHOD_NAMES),
            None,
        )
        if dispatch_method is None:
            return False

        private_methods = [
            m for m in methods
            if not str(m.name or "").startswith("__") and str(m.visibility or "public").lower() != "public"
        ]
        if len(private_methods) < 4 or len(private_methods) > 20:
            return False

        private_method_names = [str(m.name or "").lower() for m in private_methods]
        dispatch_calls = [str(call or "").lower() for call in (dispatch_method.call_sites or [])]
        helper_dispatches = sum(
            1
            for helper_name in private_method_names
            if any(f"->{helper_name}(" in call or helper_name + "(" in call for call in dispatch_calls)
        )
        if helper_dispatches < min(3, len(private_method_names)):
            return False

        delegated_private = 0
        for method in private_methods:
            call_sites = [str(call or "").lower() for call in (method.call_sites or [])]
            if any(any(marker in call for marker in self._DELEGATION_CALL_MARKERS) for call in call_sites):
                delegated_private += 1

        private_delegation_ratio = delegated_private / len(private_methods)
        if private_delegation_ratio < 0.6:
            return False

        avg_public_loc = (
            sum((m.loc or max(0, (m.line_end or 0) - (m.line_start or 0) + 1)) for m in public_methods)
            / len(public_methods)
        )
        avg_private_loc = (
            sum((m.loc or max(0, (m.line_end or 0) - (m.line_start or 0) + 1)) for m in private_methods)
            / len(private_methods)
        )
        return avg_public_loc <= 70 and avg_private_loc <= 35
