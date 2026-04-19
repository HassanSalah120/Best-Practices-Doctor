"""
Controller Query Direct Rule

Flags direct DB/Eloquent queries inside controller actions.
This is distinct from repository-suggestion (advisory): this is a violation.
"""
from schemas.facts import Facts, QueryUsage
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, FindingClassification, Category, Severity
from rules.base import Rule
from core.project_recommendations import enabled_team_standards


class ControllerQueryDirectRule(Rule):
    """
    Detects direct queries inside controllers (layering violation).

    Heuristic: any QueryUsage whose file belongs to a controller.
    Threshold is configurable per method.
    """

    id = "controller-query-direct"
    name = "Controller Should Not Query DB Directly"
    description = "Detects direct Eloquent/DB query usage inside controllers"
    category = Category.LARAVEL_BEST_PRACTICE
    default_severity = Severity.HIGH
    default_classification = FindingClassification.ADVISORY
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    _SIMPLE_READ_TOKENS = {"query", "find", "findorfail", "first", "get", "all", "paginate", "pluck", "count", "exists"}
    _RESTFUL_READ_METHODS = {"index", "show", "create", "edit"}
    _PUBLIC_METHOD_NAMES = {"login", "logout", "register", "forgotpassword", "resetpassword", "webhook"}
    _DELEGATION_MARKERS = (
        "->execute(",
        "->handle(",
        "->run(",
        "service->",
        "services->",
        "action->",
        "actions->",
        "coordinator->",
        "workflow->",
        "repository->",
        "repositories->",
    )

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Any query in controller is a violation by default.
        max_queries = int(self.get_threshold("max_queries_per_method", 0))
        project_context = getattr(facts, "project_context", None)
        architecture_profile = str(getattr(project_context, "backend_architecture_profile", "unknown") or "unknown").lower()
        if architecture_profile == "unknown":
            architecture_profile = str(getattr(project_context, "backend_structure_mode", "unknown") or "unknown").lower()
        team_standards = enabled_team_standards(facts)
        if architecture_profile == "mvc" and "thin_controllers" not in team_standards and "repositories_expected" not in team_standards:
            max_queries = max(max_queries, 2)

        controller_files = {c.file_path for c in facts.controllers}
        if not controller_files:
            return findings

        # Group queries by (file, method) to avoid noise.
        grouped: dict[tuple[str, str], list[QueryUsage]] = {}
        for q in facts.queries:
            if q.file_path not in controller_files:
                continue
            grouped.setdefault((q.file_path, q.method_name), []).append(q)

        # Map file -> controller fqcn best-effort.
        fqcn_by_file: dict[str, str] = {}
        for c in facts.controllers:
            fqcn_by_file.setdefault(c.file_path, c.fqcn)
        methods_by_key = {
            (m.file_path, (m.name or "").lower()): m
            for m in facts.methods
            if m.file_path in controller_files and m.name
        }

        for (file_path, method_name), qs in grouped.items():
            normalized_name = (method_name or "").lower()
            if normalized_name in self._PUBLIC_METHOD_NAMES:
                continue
            method_info = methods_by_key.get((file_path, normalized_name))
            if self._is_delegated_controller_read(method_info, qs, normalized_name):
                continue

            if len(qs) == 1 and self._is_simple_controller_read(qs[0], normalized_name):
                continue
            if len(qs) <= max_queries:
                continue

            line_start = min(q.line_number for q in qs)
            controller_fqcn = fqcn_by_file.get(file_path, "")
            ctx = f"{controller_fqcn}::{method_name}" if controller_fqcn else f"{file_path}:{method_name}"
            overlap_scope = method_info.method_fqn if method_info is not None else ctx

            # Show a short sample of the query chain(s).
            sample = ", ".join(sorted({(q.model or "DB") + ":" + (q.method_chain or "query") for q in qs})[:3])
            if len(qs) > 3:
                sample += f", +{len(qs) - 3} more"

            findings.append(
                self.create_finding(
                    title="Database query directly in controller",
                    context=ctx,
                    file=file_path,
                    line_start=line_start,
                    description=(
                        f"Detected {len(qs)} query call(s) inside a controller method. "
                        "Controllers should orchestrate, not query the database directly. "
                        f"Examples: {sample}."
                    ),
                    why_it_matters=(
                        "DB queries in controllers make code harder to test, reuse, and optimize. "
                        "Moving data access to repositories/query objects or services keeps controllers thin and consistent."
                    ),
                    suggested_fix=(
                        "1. Move query logic into a Repository/Query class or a Service/Action\n"
                        "2. Inject the dependency via the constructor\n"
                        "3. Keep controller methods focused on request/response mapping\n"
                        "4. Add unit tests for the extracted layer"
                    ),
                    tags=["laravel", "architecture", "controllers", "repositories", "queries"],
                    classification=FindingClassification.ADVISORY,
                    metadata={
                        "decision_profile": {
                            "decision": "emit",
                            "architecture_profile": architecture_profile or "unknown",
                            "team_standards": sorted(team_standards),
                            "decision_summary": "Controller query density exceeded context-aware threshold without safe delegation.",
                            "decision_reasons": [
                                f"query_count={len(qs)}",
                                f"max_queries_per_method={max_queries}",
                            ],
                        },
                        "overlap_group": "controller-layering",
                        "overlap_scope": overlap_scope,
                        "overlap_rank": 140,
                        "overlap_role": "child",
                    },
                )
            )

        return findings

    def _is_simple_controller_read(self, query: QueryUsage, method_name: str) -> bool:
        if (query.query_type or "select").lower() != "select":
            return False
        if query.is_raw or query.has_eager_loading:
            return False
        if method_name not in self._RESTFUL_READ_METHODS:
            return False

        tokens = [token.strip().lower() for token in (query.method_chain or "").split("->") if token.strip()]
        if not tokens:
            return False
        return all(token in self._SIMPLE_READ_TOKENS for token in tokens)

    def _is_delegated_controller_read(
        self,
        method,
        queries: list[QueryUsage],
        method_name: str,
    ) -> bool:
        if method is None:
            return False
        if any((query.query_type or "select").lower() != "select" for query in queries):
            return False
        if len(queries) > 1:
            return False

        call_sites = [str(cs or "").lower() for cs in (method.call_sites or [])]
        has_delegation = any(any(marker in cs for marker in self._DELEGATION_MARKERS) for cs in call_sites)
        if not has_delegation:
            return False

        return method_name in self._RESTFUL_READ_METHODS or int(getattr(method, "loc", 0) or 0) <= 18
