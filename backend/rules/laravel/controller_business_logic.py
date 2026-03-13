"""
Controller Business Logic Rule

Flags complex/business logic inside controllers as a layering violation.
Uses derived metrics (complexity + business logic heuristics); does not parse source.
"""
from schemas.facts import Facts, MethodInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, FindingClassification, Category, Severity
from rules.base import Rule


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
        "service->",
        "services->",
        "action->",
        "actions->",
        "coordinator->",
        "workflow->",
        "processor->",
        "redirector->",
        "redirectvalidator->",
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
        auth_flow_context = set(getattr(getattr(facts, "project_context", None), "auth_flow_paths", []) or [])

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
            if not has_business_signal and not has_structural_signal:
                continue
            if self._looks_like_thin_orchestration(m, mm, auth_flow_context):
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
                    ),
                    tags=["architecture", "controllers", "services", "actions"],
                    classification=FindingClassification.ADVISORY,
                    confidence=confidence,
                    metadata={
                        "overlap_group": "controller-layering",
                        "overlap_scope": m.method_fqn,
                        "overlap_rank": 200,
                        "overlap_role": "child",
                    },
                )
            )

        return findings

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
    ) -> bool:
        if metrics.loop_count > 0 or metrics.has_file_operations:
            return False

        call_sites = [str(call or "").lower() for call in (method.call_sites or [])]
        has_delegation = any(marker in call for call in call_sites for marker in self._DELEGATION_CALL_MARKERS)
        if not has_delegation:
            return False

        normalized_path = str(method.file_path or "").replace("\\", "/").lower()
        method_fqn = str(method.method_fqn or "")
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

        return (
            simple_guards
            and (method.loc or 0) <= 75
            and sum(1 for call in call_sites if any(marker in call for marker in self._RESPONSE_ORCHESTRATION_MARKERS)) <= 6
            and not metrics.has_external_api_calls
        )
