"""
Controller Business Logic Rule

Flags complex/business logic inside controllers as a layering violation.
Uses derived metrics (complexity + business logic heuristics); does not parse source.
"""
from schemas.facts import Facts, MethodInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, FindingClassification, Category, Severity
from rules.base import Rule
from core.project_recommendations import (
    enabled_capabilities,
    enabled_team_standards,
    project_aware_guidance,
    recommendation_context_tags,
)


class ControllerBusinessLogicRule(Rule):
    """
    Detects controller methods that contain significant business logic.

    Uses MethodMetrics derived from AST:
    - cyclomatic complexity
    - business logic flag/confidence
    """

    id = "controller-business-logic"
    name = "Business Logic In Controller"
    description = "Detects complex/business logic inside controllers"
    category = Category.ARCHITECTURE
    default_severity = Severity.HIGH
    default_classification = FindingClassification.ADVISORY
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    _RESTFUL_READ_METHODS = {"index", "show", "create", "edit"}
    _INFRA_CONTROLLER_MARKERS = ("webhook", "callback", "verification", "twofactor", "two_factor", "notification")
    _DELEGATION_CALL_MARKERS = (
        "->execute(",
        "->handle(",
        "->run(",
        "service->",
        "services->",
        "action->",
        "actions->",
        "coordinator->",
        "workflow->",
        "processor->",
        "redirector->",
        "redirectvalidator->",
        "repository->",
        "repositories->",
        "validatesignature->",
        "processwebhook->",
        "sendverification->",
        "sendcode->",
        "resolve",
        "sanitize(",
    )
    _RESPONSE_ORCHESTRATION_MARKERS = (
        "redirect()->",
        "return back(",
        "with(",
        "response()->",
        "abort(",
    )
    _HEAVY_BUSINESS_MARKERS = (
        "calculate",
        "compute",
        "transform",
        "rebalance",
        "rank",
        "assign",
        "reconcile",
        "allocate",
        "provision",
        "flagforreview",
        "discount",
        "score",
    )

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        if not metrics:
            return findings

        controller_files = {c.file_path for c in facts.controllers}
        if not controller_files:
            return findings

        min_cyclomatic = int(self.get_threshold("min_cyclomatic", 8))
        min_loc = int(self.get_threshold("min_loc", 60))
        min_conf = float(self.get_threshold("min_confidence", 0.6))
        project_context = getattr(facts, "project_context", None)
        project_business_context = str(getattr(project_context, "project_business_context", "unknown") or "unknown")
        capabilities = enabled_capabilities(facts)
        team_standards = enabled_team_standards(facts)
        if "thin_controllers" in team_standards:
            min_cyclomatic = max(5, min_cyclomatic - 1)
            min_loc = max(45, min_loc - 10)
        if project_business_context in {"saas_platform", "clinic_erp_management", "realtime_game_control_platform"}:
            min_loc = max(45, min_loc - 5)

        auth_flow_context = set(getattr(project_context, "auth_flow_paths", []) or [])
        architecture_profile = str(getattr(project_context, "backend_architecture_profile", "unknown") or "unknown").lower()
        if architecture_profile == "unknown":
            architecture_profile = "layered" if str(getattr(project_context, "backend_structure_mode", "unknown") or "unknown").lower() == "layered" else "unknown"
        profile_confidence = float(getattr(project_context, "backend_profile_confidence", 0.0) or 0.0)
        profile_confidence_kind = str(getattr(project_context, "backend_profile_confidence_kind", "unknown") or "unknown")
        profile_signals = list(getattr(project_context, "backend_profile_signals", []) or [])

        # Best-effort map file -> controller fqcn.
        fqcn_by_file: dict[str, str] = {}
        for c in facts.controllers:
            fqcn_by_file.setdefault(c.file_path, c.fqcn)

        for m in facts.methods:
            if m.file_path not in controller_files:
                continue
            if m.name.startswith("__"):
                continue

            mm = metrics.get(m.method_fqn)
            if not mm:
                continue

            has_business_signal = (
                mm.has_business_logic
                and mm.business_logic_confidence >= min_conf
                and (
                    mm.cyclomatic_complexity >= 2
                    or (m.loc or 0) >= max(15, min_loc // 2)
                    or (mm.query_count + mm.validation_count + mm.conditional_count + mm.loop_count) >= 2
                )
            )
            has_structural_signal = (
                mm.cyclomatic_complexity >= min_cyclomatic
                and (m.loc or 0) >= min_loc
                and (mm.conditional_count >= 4 or mm.loop_count >= 1)
            )
            decision_profile = self._decision_profile(
                m,
                mm,
                auth_flow_context,
                architecture_profile,
                has_business_signal,
                has_structural_signal,
                profile_confidence=profile_confidence,
                profile_confidence_kind=profile_confidence_kind,
                profile_signals=profile_signals,
                project_business_context=project_business_context,
                capabilities=capabilities,
                team_standards=team_standards,
            )
            if not has_business_signal and not has_structural_signal:
                continue
            if decision_profile["suppressed_as_thin_orchestration"]:
                continue
            if self._looks_like_restful_read_controller_method(m, mm) and not has_business_signal:
                continue
            if (
                not has_business_signal
                and mm.query_count <= 1
                and mm.validation_count >= 1
                and mm.conditional_count < 5
                and mm.loop_count == 0
                and not mm.has_external_api_calls
                and not mm.has_file_operations
            ):
                continue

            controller_fqcn = fqcn_by_file.get(m.file_path, "")
            ctx = m.method_fqn if controller_fqcn else f"{m.file_path}:{m.name}"

            confidence = 0.65
            if mm.has_business_logic:
                confidence = max(confidence, min(1.0, 0.5 + mm.business_logic_confidence / 2))
            else:
                # Controllers often mix validation/queries with branching; treat CC/LOC as primary signal.
                confidence = max(confidence, min(0.9, 0.5 + (mm.cyclomatic_complexity / 20)))
            guidance = project_aware_guidance(facts, focus="controller_boundaries")
            severity = self._calibrated_severity(project_business_context, capabilities, team_standards)

            findings.append(
                self.create_finding(
                    title="Business logic should be extracted from controller",
                    context=ctx,
                    file=m.file_path,
                    line_start=m.line_start,
                    line_end=m.line_end,
                    description=(
                        f"Controller method `{m.name}` appears to contain business logic "
                        f"(CC={mm.cyclomatic_complexity}, LOC={m.loc}). "
                        "Consider extracting this logic into a Service or Action class."
                    ),
                    why_it_matters=(
                        "Controllers should stay thin so they are easy to read, test, and evolve. "
                        "Business logic in controllers tends to get duplicated and makes refactors risky."
                    ),
                    suggested_fix=(
                        "Rule of thumb:\n"
                        "- If the operation is reusable, small, and used in more than one service: make it an Action.\n"
                        "- If it represents a full use-case/workflow: make it a Service.\n"
                        "\n"
                        "1. Extract the core logic to an `App\\Services\\...` Service or an `Action` class\n"
                        "2. Inject the service/action into the controller\n"
                        "3. Keep the controller method as orchestration (request -> call -> response)\n"
                        "4. Add unit tests for the extracted logic"
                    ) + (f"\n\nProject-aware guidance:\n{guidance}" if guidance else ""),
                    tags=["architecture", "controllers", "services", "actions", *recommendation_context_tags(facts)],
                    severity=severity,
                    classification=FindingClassification.ADVISORY,
                    confidence=confidence,
                    evidence_signals=decision_profile["evidence_signals"],
                    metadata={
                        "decision_profile": decision_profile,
                        "backend_framework": decision_profile["backend_framework"],
                        "architecture_profile": decision_profile["architecture_profile"],
                        "decision_reasons": decision_profile["decision_reasons"],
                        "suppression_checks": decision_profile["suppression_checks"],
                        "overlap_group": "controller-layering",
                        "overlap_scope": m.method_fqn,
                        "overlap_rank": 200,
                        "overlap_role": "child",
                    },
                )
            )

        return findings

    def _decision_profile(
        self,
        method: MethodInfo,
        metrics: MethodMetrics,
        auth_flow_context: set[str],
        architecture_profile: str | bool,
        has_business_signal: bool,
        has_structural_signal: bool,
        profile_confidence: float = 0.0,
        profile_confidence_kind: str = "unknown",
        profile_signals: list[str] | None = None,
        project_business_context: str = "unknown",
        capabilities: set[str] | None = None,
        team_standards: set[str] | None = None,
    ) -> dict[str, object]:
        profile = self._normalize_architecture_profile(architecture_profile)
        capabilities = set(capabilities or set())
        team_standards = set(team_standards or set())
        thin_orchestration = self._looks_like_thin_orchestration(method, metrics, auth_flow_context, profile)
        decision = "suppress" if thin_orchestration else ("emit" if (has_business_signal or has_structural_signal) else "skip")
        suppression_reason = "thin-orchestration" if thin_orchestration else None
        emission_reason = None
        if decision == "emit":
            if has_business_signal and has_structural_signal:
                emission_reason = "business-and-structural-signals"
            elif has_business_signal:
                emission_reason = "business-signal-without-safe-orchestration"
            else:
                emission_reason = "structural-signal-without-safe-orchestration"
        return {
            "backend_framework": "laravel",
            "architecture_profile": profile,
            "profile_confidence": round(float(profile_confidence or 0.0), 2),
            "profile_confidence_kind": str(profile_confidence_kind or "unknown"),
            "profile_signals": list(profile_signals or [])[:8],
            "project_business_context": project_business_context,
            "capabilities": sorted(capabilities),
            "team_standards": sorted(team_standards),
            "decision": decision,
            "decision_summary": (
                f"{decision} under {profile} profile"
                + (f" because {suppression_reason}" if suppression_reason else "")
                + (f" because {emission_reason}" if emission_reason else "")
            ),
            "suppression_reason": suppression_reason,
            "emission_reason": emission_reason,
            "decision_reasons": [
                reason
                for enabled, reason in (
                    (has_business_signal, "business-signal"),
                    (has_structural_signal, "structural-signal"),
                    (thin_orchestration, "thin-orchestration"),
                )
                if enabled
            ],
            "suppression_checks": {
                "thin_orchestration": thin_orchestration,
                "restful_read": self._looks_like_restful_read_controller_method(method, metrics),
            },
            "suppressed_as_thin_orchestration": thin_orchestration,
            "evidence_signals": [
                "framework=laravel",
                f"profile={profile}",
                f"profile_confidence={float(profile_confidence or 0.0):.2f}",
                f"profile_confidence_kind={profile_confidence_kind or 'unknown'}",
                f"business_context={project_business_context or 'unknown'}",
                f"capabilities={','.join(sorted(capabilities)) or 'none'}",
                f"team_standards={','.join(sorted(team_standards)) or 'none'}",
                f"cc={metrics.cyclomatic_complexity}",
                f"loc={method.loc or 0}",
                f"queries={metrics.query_count}",
                f"validation={metrics.validation_count}",
                f"delegation={int(any(marker in str(call or '').lower() for call in (method.call_sites or []) for marker in self._DELEGATION_CALL_MARKERS))}",
            ],
        }

    def _calibrated_severity(self, project_business_context: str, capabilities: set[str], team_standards: set[str]) -> Severity:
        if "thin_controllers" in team_standards:
            return Severity.HIGH
        if project_business_context in {"saas_platform", "clinic_erp_management", "realtime_game_control_platform", "portal_based_business_app"}:
            return Severity.HIGH
        if {"multi_tenant", "multi_role_portal"} & set(capabilities):
            return Severity.HIGH
        return self.severity

    def _looks_like_restful_read_controller_method(self, method: MethodInfo, metrics: MethodMetrics) -> bool:
        method_name = (method.name or "").lower()
        if method_name not in self._RESTFUL_READ_METHODS:
            return False
        return (
            metrics.query_count <= 1
            and metrics.validation_count <= 1
            and not metrics.has_external_api_calls
            and not metrics.has_file_operations
            and metrics.loop_count == 0
        )

    def _looks_like_thin_orchestration(
        self,
        method: MethodInfo,
        metrics: MethodMetrics,
        auth_flow_context: set[str],
        architecture_profile: str,
    ) -> bool:
        if metrics.loop_count > 0 or metrics.has_file_operations:
            return False

        call_sites = [str(call or "").lower() for call in (method.call_sites or [])]
        has_delegation = any(marker in call for call in call_sites for marker in self._DELEGATION_CALL_MARKERS)
        if not has_delegation:
            return False
        has_heavy_logic = any(marker in call for call in call_sites for marker in self._HEAVY_BUSINESS_MARKERS)
        if has_heavy_logic:
            return False

        normalized_path = str(method.file_path or "").replace("\\", "/").lower()
        method_fqn = str(method.method_fqn or "")
        layered_like = architecture_profile in {"layered", "modular"}
        api_first = architecture_profile == "api-first"
        mvc_profile = architecture_profile == "mvc"
        is_auth_flow = (
            method_fqn in auth_flow_context
            or str(method.file_path or "") in auth_flow_context
            or any(marker in normalized_path for marker in self._INFRA_CONTROLLER_MARKERS)
        )

        simple_guards = (
            metrics.cyclomatic_complexity <= 4
            and metrics.conditional_count <= 3
            and metrics.query_count <= 1
            and metrics.validation_count <= 1
        )
        if is_auth_flow and simple_guards:
            return True

        layered_orchestration = (
            layered_like
            and has_delegation
            and metrics.query_count <= 1
            and metrics.validation_count <= 1
            and metrics.conditional_count <= 4
            and metrics.cyclomatic_complexity <= 6
            and (method.loc or 0) <= 90
            and sum(1 for call in call_sites if any(marker in call for marker in self._RESPONSE_ORCHESTRATION_MARKERS)) >= 1
        )
        if layered_orchestration:
            return True

        api_orchestration = (
            api_first
            and has_delegation
            and metrics.query_count <= 1
            and metrics.validation_count <= 2
            and metrics.conditional_count <= 4
            and metrics.cyclomatic_complexity <= 7
            and (method.loc or 0) <= 95
            and any(marker in call for call in call_sites for marker in ("response()->", "json", "resource", "resourcecollection", "return ["))
        )
        if api_orchestration:
            return True

        mvc_orchestration = (
            mvc_profile
            and has_delegation
            and metrics.query_count <= 1
            and metrics.validation_count <= 1
            and metrics.conditional_count <= 3
            and metrics.cyclomatic_complexity <= 5
            and (method.loc or 0) <= 65
        )
        if mvc_orchestration:
            return True

        return (
            simple_guards
            and (method.loc or 0) <= 75
            and sum(1 for call in call_sites if any(marker in call for marker in self._RESPONSE_ORCHESTRATION_MARKERS)) <= 6
            and not metrics.has_external_api_calls
        )

    def _normalize_architecture_profile(self, architecture_profile: str | bool) -> str:
        if isinstance(architecture_profile, bool):
            return "layered" if architecture_profile else "unknown"
        profile = str(architecture_profile or "unknown").lower()
        return profile if profile in {"mvc", "layered", "modular", "api-first"} else "unknown"
