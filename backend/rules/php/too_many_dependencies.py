"""
Too Many Dependencies Rule

Flags constructors with too many injected dependencies (tight coupling / SRP smell).
"""
from schemas.facts import Facts, MethodInfo
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


class TooManyDependenciesRule(Rule):
    """
    Detects constructors with too many parameters (dependencies).
    """

    id = "too-many-dependencies"
    name = "Too Many Constructor Dependencies"
    description = "Detects constructors with too many dependencies (likely SRP violation)"
    category = Category.MAINTAINABILITY
    default_severity = Severity.MEDIUM
    applicable_project_types: list[str] = []  # all
    _SERVICE_LIKE_PARAM_MARKERS = (
        "action",
        "service",
        "coordinator",
        "workflow",
        "orchestrator",
        "dispatcher",
        "broker",
        "scheduler",
        "validator",
        "redirector",
        "interface",
        "manager",
        "gateway",
        "repository",
        "queue",
        "token",
        "command",
        "connection",
        "circuitbreaker",
        "visibility",
        "event",
        "handler",
        "publisher",
        "transport",
        "store",
    )
    _SERVICE_COORDINATOR_NAME_MARKERS = (
        "server",
        "manager",
        "handler",
        "coordinator",
        "orchestrator",
        "workflow",
        "gateway",
        "dispatcher",
        "broker",
        "router",
    )
    _BOUNDED_FACADE_DEP_MARKERS = (
        "coordinator",
        "orchestrator",
        "workflow",
        "facade",
    )
    _BOUNDED_FACADE_ACTION_MARKERS = (
        "action",
        "command",
    )

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        max_deps = int(self.get_threshold("max_dependencies", 5))
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

        for m in facts.methods:
            if m.name != "__construct":
                continue
            
            # Skip DTOs - they have data properties, not service dependencies
            if self._is_dto(m, facts):
                continue
            
            # Skip orchestrators/coordinators - they intentionally coordinate multiple services
            if self._is_orchestrator(m, facts):
                continue
            if self._is_controller_facade_orchestrator(m, architecture_profile):
                continue
            if self._is_service_facade_orchestrator(m, architecture_profile):
                continue
            if self._is_bounded_service_facade(m, architecture_profile):
                continue
            
            dep_count = len(m.parameters or [])
            if dep_count <= max_deps:
                continue

            profile = self._dependency_profile(
                m,
                architecture_profile,
                profile_confidence=profile_confidence,
                profile_confidence_kind=profile_confidence_kind,
                profile_signals=profile_signals,
                business_context=business_context,
                capabilities=capabilities,
                team_standards=team_standards,
            )
            ctx = m.method_fqn
            confidence = min(0.96, 0.58 + (max(0, dep_count - max_deps) * 0.08))
            guidance = project_aware_guidance(facts, focus="orchestration_boundaries")
            severity = self._calibrated_severity(business_context, capabilities, team_standards)
            findings.append(
                self.create_finding(
                    title="Constructor has too many dependencies",
                    context=ctx,
                    file=m.file_path,
                    line_start=m.line_start,
                    line_end=m.line_end,
                    description=(
                        f"Constructor `{m.method_fqn}` has {dep_count} parameters (threshold: {max_deps}). "
                        "This often indicates a class doing too much or a missing abstraction."
                    ),
                    why_it_matters=(
                        "Classes with many dependencies are hard to test, hard to reuse, and tend to violate SRP. "
                        "They also make DI graphs brittle and increase the cost of change."
                    ),
                    suggested_fix=(
                        "1. Split responsibilities into smaller services\n"
                        "2. Introduce a Facade/Coordinator that composes smaller collaborators\n"
                        "3. Group related dependencies behind an interface\n"
                        "4. Consider an Action class per use-case"
                    ) + (f"\n\nProject-aware guidance:\n{guidance}" if guidance else ""),
                    tags=["maintainability", "srp", "coupling", "di", *recommendation_context_tags(facts)],
                    severity=severity,
                    confidence=confidence,
                    evidence_signals=profile["evidence_signals"],
                    metadata={"decision_profile": profile},
                )
            )

        return findings

    def _dependency_profile(
        self,
        method: MethodInfo,
        architecture_profile: str,
        *,
        profile_confidence: float = 0.0,
        profile_confidence_kind: str = "unknown",
        profile_signals: list[str] | None = None,
        business_context: str = "unknown",
        capabilities: set[str] | None = None,
        team_standards: set[str] | None = None,
    ) -> dict[str, object]:
        capabilities = set(capabilities or set())
        team_standards = set(team_standards or set())
        params = [str(param or "") for param in (method.parameters or [])]
        params_low = [param.lower() for param in params]
        service_like = sum(
            1 for param in params_low if any(marker in param for marker in self._SERVICE_LIKE_PARAM_MARKERS)
        )
        controller_orchestrator_shape = self._is_controller_facade_orchestrator(method, architecture_profile)
        service_orchestrator_shape = self._is_service_facade_orchestrator(method, architecture_profile)
        bounded_service_facade = self._is_bounded_service_facade(method, architecture_profile)
        return {
            "backend_framework": "laravel" if architecture_profile != "unknown" else "unknown",
            "architecture_profile": architecture_profile,
            "profile_confidence": round(float(profile_confidence or 0.0), 2),
            "profile_confidence_kind": str(profile_confidence_kind or "unknown"),
            "profile_signals": list(profile_signals or [])[:8],
            "project_business_context": business_context,
            "capabilities": sorted(capabilities),
            "team_standards": sorted(team_standards),
            "dependency_count": len(params),
            "service_like_dependencies": service_like,
            "controller_orchestrator_shape": controller_orchestrator_shape,
            "service_orchestrator_shape": service_orchestrator_shape,
            "bounded_service_facade": bounded_service_facade,
            "decision": "emit",
            "decision_summary": "emit because dependency-count-exceeded without coordinator suppression",
            "evidence_signals": [
                f"profile={architecture_profile}",
                f"profile_confidence={float(profile_confidence or 0.0):.2f}",
                f"profile_confidence_kind={profile_confidence_kind or 'unknown'}",
                f"business_context={business_context or 'unknown'}",
                f"capabilities={','.join(sorted(capabilities)) or 'none'}",
                f"team_standards={','.join(sorted(team_standards)) or 'none'}",
                f"deps={len(params)}",
                f"service_like={service_like}",
                f"bounded_service_facade={int(bounded_service_facade)}",
            ],
        }

    def _calibrated_severity(self, business_context: str, capabilities: set[str], team_standards: set[str]) -> Severity:
        if business_context in {"realtime_game_control_platform", "saas_platform"}:
            return Severity.HIGH
        if {"realtime", "billing", "queue_heavy"} & set(capabilities):
            return Severity.HIGH
        if "services_actions_expected" in team_standards:
            return Severity.HIGH
        return self.severity
    
    def _is_dto(self, method: MethodInfo, facts: Facts) -> bool:
        """Check if the class is a DTO (Data Transfer Object) - these have data properties, not service dependencies."""
        # Check file path for DTO markers
        if method.file_path:
            path_lower = method.file_path.lower().replace("\\", "/")
            if "/dto/" in path_lower or "/dtos/" in path_lower:
                return True
            # Check filename
            filename = path_lower.split("/")[-1] if "/" in path_lower else path_lower
            if "dto" in filename.lower():
                return True
        
        # Check if class name ends with DTO
        if method.class_name and method.class_name.lower().endswith("dto"):
            return True
        
        return False

    def _is_orchestrator(self, method: MethodInfo, facts: Facts) -> bool:
        """Check if the class is an orchestrator/coordinator - these intentionally have many dependencies."""
        class_name = (method.class_name or "").lower()
        
        # Check class name patterns for orchestrator/coordinator
        orchestrator_patterns = [
            "coordinator",
            "orchestrator",
            "workflow",
            "processmanager",
            "saga",
        ]
        if any(pattern in class_name for pattern in orchestrator_patterns):
            return True
        
        # Check for service classes that orchestrate multi-step workflows
        # These typically have names like InsuranceClaimService, OrderProcessingService
        workflow_service_patterns = [
            "claimservice",
            "orderservice",
            "processingservice",
            "workflowservice",
            "financialservice",
        ]
        if any(pattern in class_name for pattern in workflow_service_patterns):
            return True
        
        # Check file path for coordination/workflow folders
        if method.file_path:
            path_lower = method.file_path.lower().replace("\\", "/")
            if "/coordination/" in path_lower or "/workflows/" in path_lower or "/workflow/" in path_lower:
                return True
        
        return False

    def _is_controller_facade_orchestrator(self, method: MethodInfo, architecture_profile: str) -> bool:
        path_lower = str(method.file_path or "").lower().replace("\\", "/")
        if "/controller" not in path_lower and "/controllers/" not in path_lower:
            return False

        params = [str(param or "").lower() for param in (method.parameters or [])]
        if len(params) < 6:
            return False

        service_like = sum(
            1
            for param in params
            if any(marker in param for marker in self._SERVICE_LIKE_PARAM_MARKERS)
        )
        if service_like < max(4, len(params) - 1):
            return False

        action_or_service_contracts = sum(
            1
            for param in params
            if any(marker in param for marker in ("action", "serviceinterface", "repositoryinterface", "coordinator", "orchestrator"))
        )

        if any(marker in param for param in params for marker in ("coordinator", "orchestrator", "facade")):
            return True

        if (
            architecture_profile == "unknown"
            and len(params) <= 7
            and service_like == len(params)
            and action_or_service_contracts >= max(3, len(params) // 2)
        ):
            return True

        return architecture_profile in {"layered", "modular", "api-first"} and len(params) <= 7

    def _is_service_facade_orchestrator(self, method: MethodInfo, architecture_profile: str) -> bool:
        path_lower = str(method.file_path or "").lower().replace("\\", "/")
        class_name = str(method.class_name or "").lower()
        has_coordinator_name = any(marker in class_name for marker in self._SERVICE_COORDINATOR_NAME_MARKERS)
        has_coordinator_path = any(
            marker in path_lower for marker in ("/workflow/", "/workflows/", "/coordination/", "/orchestrators/", "/servers/")
        )
        layered_like = architecture_profile in {"layered", "modular"}
        if not (has_coordinator_name or has_coordinator_path or (layered_like and "/services/" in path_lower and "server" in class_name)):
            return False

        params = [str(param or "").lower() for param in (method.parameters or [])]
        if len(params) < 6:
            return False

        service_like = sum(
            1 for param in params if any(marker in param for marker in self._SERVICE_LIKE_PARAM_MARKERS)
        )
        if service_like < max(5, len(params) - 1):
            return False

        if architecture_profile == "mvc":
            return any(marker in class_name for marker in ("coordinator", "orchestrator", "workflow"))
        return len(params) <= 8 if architecture_profile not in {"layered", "modular"} else len(params) <= 9

    def _is_bounded_service_facade(self, method: MethodInfo, architecture_profile: str) -> bool:
        path_lower = str(method.file_path or "").lower().replace("\\", "/")
        class_name = str(method.class_name or "").lower()
        if "/services/" not in path_lower or not class_name.endswith("service"):
            return False
        if architecture_profile not in {"layered", "modular", "unknown"}:
            return False

        params = [str(param or "").lower() for param in (method.parameters or [])]
        dep_count = len(params)
        if dep_count < 6 or dep_count > 7:
            return False

        service_like = sum(
            1 for param in params if any(marker in param for marker in self._SERVICE_LIKE_PARAM_MARKERS)
        )
        facade_like = sum(
            1 for param in params if any(marker in param for marker in self._BOUNDED_FACADE_DEP_MARKERS)
        )
        action_like = sum(
            1 for param in params if any(marker in param for marker in self._BOUNDED_FACADE_ACTION_MARKERS)
        )

        if service_like < max(4, dep_count - 1):
            return False
        return facade_like >= 1 or action_like >= 2
