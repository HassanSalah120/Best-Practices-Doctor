from pathlib import Path

from analysis.facts_builder import FactsBuilder
from analysis.metrics_analyzer import MetricsAnalyzer
from core.detector import ProjectDetector
from core.rule_engine import ALL_RULES, create_engine
from core.ruleset import RuleConfig, Ruleset
from rules.laravel.controller_business_logic import ControllerBusinessLogicRule
from rules.laravel.service_extraction import ServiceExtractionRule
from rules.php.god_class import GodClassRule
from rules.php.too_many_dependencies import TooManyDependenciesRule
from rules.react.large_component import LargeComponentRule
from rules.react.no_inline_services import NoInlineServicesRule
from rules.react.project_structure_consistency import ReactProjectStructureConsistencyRule
from schemas.facts import ClassInfo, Facts, MethodInfo, ReactComponentInfo
from schemas.metrics import MethodMetrics


def _ruleset_for(rule_ids: list[str]) -> Ruleset:
    rules = {rid: RuleConfig(enabled=False) for rid in ALL_RULES.keys()}
    for rule_id in rule_ids:
        rules[rule_id] = RuleConfig(enabled=True)
    return Ruleset(rules=rules, name="balanced")


def _build_fixture(fixture_path: Path, fixture_name: str):
    project_root = fixture_path / fixture_name
    info = ProjectDetector(str(project_root)).detect()
    facts = FactsBuilder(info).build()
    metrics = MetricsAnalyzer().analyze(facts)
    return info, facts, metrics


def test_imposter_inertia_architecture_fixture_produces_no_findings(fixture_path: Path):
    rule_ids = [
        "controller-business-logic",
        "service-extraction",
        "too-many-dependencies",
        "god-class",
        "large-react-component",
        "no-inline-services",
        "react-project-structure-consistency",
    ]
    info, facts, metrics = _build_fixture(fixture_path, "imposter-inertia-architecture-mini")
    engine = create_engine(ruleset=_ruleset_for(rule_ids), selected_rules=rule_ids)

    result = engine.run(facts, metrics=metrics, project_type=info.project_type.value)

    assert result.findings == [], [f"{finding.rule_id}:{finding.file}" for finding in result.findings]


def test_imposter_inertia_architecture_context_is_detected(fixture_path: Path):
    _, facts, _ = _build_fixture(fixture_path, "imposter-inertia-architecture-mini")

    assert facts.project_context.backend_structure_mode == "layered"
    assert {"actions", "services", "repositories", "dto", "providers"}.issubset(set(facts.project_context.backend_layers))
    assert facts.project_context.react_structure_mode == "hybrid"
    assert {"hooks", "services", "components"}.issubset(set(facts.project_context.react_shared_roots))


def test_controller_business_logic_still_flags_real_logic_in_layered_controller():
    facts = Facts(project_path=".")
    facts.project_context.backend_structure_mode = "layered"
    facts.project_context.backend_layers = ["actions", "services", "repositories", "dto", "providers"]
    controller = ClassInfo(
        name="AdminRoundController",
        fqcn="App\\Http\\Controllers\\AdminRoundController",
        file_path="app/Http/Controllers/AdminRoundController.php",
        file_hash="ctrl",
        line_start=1,
        line_end=140,
    )
    method = MethodInfo(
        name="store",
        class_name=controller.name,
        class_fqcn=controller.fqcn,
        method_fqn=f"{controller.fqcn}::store",
        file_path=controller.file_path,
        file_hash="ctrl",
        line_start=20,
        line_end=110,
        loc=91,
        call_sites=[
            "$this->roundService->calculateScores($payload)",
            "$this->roundService->processVotes($payload)",
            "$session->participants()->get()",
            "$session->save()",
        ],
    )
    facts.controllers.append(controller)
    facts.methods.extend(
        [
            MethodInfo(
                name="__construct",
                class_name=controller.name,
                class_fqcn=controller.fqcn,
                method_fqn=f"{controller.fqcn}::__construct",
                file_path=controller.file_path,
                file_hash="ctrl",
                line_start=8,
                line_end=18,
                loc=11,
                parameters=["RoundService $roundService", "GameSessionRepository $sessions"],
            ),
            method,
        ]
    )
    metrics = {
        method.method_fqn: MethodMetrics(
            method_fqn=method.method_fqn,
            file_path=method.file_path,
            cyclomatic_complexity=10,
            conditional_count=5,
            query_count=2,
            validation_count=1,
            loop_count=1,
            has_business_logic=True,
            business_logic_confidence=0.88,
        )
    }

    findings = ControllerBusinessLogicRule(RuleConfig()).analyze(facts, metrics)
    assert any(f.rule_id == "controller-business-logic" for f in findings)


def test_service_extraction_still_flags_real_logic_in_layered_controller():
    facts = Facts(project_path=".")
    facts.project_context.backend_structure_mode = "layered"
    facts.controllers.append(
        ClassInfo(
            name="AdminRoundController",
            fqcn="App\\Http\\Controllers\\AdminRoundController",
            file_path="app/Http/Controllers/AdminRoundController.php",
            file_hash="ctrl",
            line_start=1,
            line_end=140,
        )
    )
    facts.methods.extend(
        [
            MethodInfo(
                name="__construct",
                class_name="AdminRoundController",
                class_fqcn="App\\Http\\Controllers\\AdminRoundController",
                method_fqn="App\\Http\\Controllers\\AdminRoundController::__construct",
                file_path="app/Http/Controllers/AdminRoundController.php",
                file_hash="ctrl",
                line_start=8,
                line_end=18,
                loc=11,
                parameters=["RoundService $roundService", "GameSessionRepository $sessions"],
            ),
            MethodInfo(
                name="store",
                class_name="AdminRoundController",
                class_fqcn="App\\Http\\Controllers\\AdminRoundController",
                method_fqn="App\\Http\\Controllers\\AdminRoundController::store",
                file_path="app/Http/Controllers/AdminRoundController.php",
                file_hash="ctrl",
                line_start=20,
                line_end=90,
                loc=71,
                call_sites=[
                    "$this->roundService->calculateScores($payload)",
                    "$this->roundService->processVotes($payload)",
                    "$session->save()",
                    "return back()->with('success', 'saved')",
                ],
            ),
        ]
    )
    metrics = {
        "App\\Http\\Controllers\\AdminRoundController::store": MethodMetrics(
            method_fqn="App\\Http\\Controllers\\AdminRoundController::store",
            file_path="app/Http/Controllers/AdminRoundController.php",
            cyclomatic_complexity=8,
            conditional_count=4,
            loop_count=1,
            has_business_logic=True,
            business_logic_confidence=0.82,
        )
    }

    findings = ServiceExtractionRule(RuleConfig(thresholds={"min_business_loc": 15})).analyze(facts, metrics)
    assert any(f.rule_id == "service-extraction" for f in findings)


def test_too_many_dependencies_still_flags_non_coordinator_service_in_layered_backend():
    facts = Facts(project_path=".")
    facts.project_context.backend_structure_mode = "layered"
    ctor = MethodInfo(
        name="__construct",
        class_name="BloatedMatchService",
        class_fqcn="App\\Services\\Analytics\\BloatedMatchService",
        method_fqn="App\\Services\\Analytics\\BloatedMatchService::__construct",
        file_path="app/Services/Analytics/BloatedMatchService.php",
        file_hash="svc",
        line_start=10,
        line_end=25,
        loc=16,
        parameters=[
            "GameSessionRepository $sessions",
            "PlayerRepository $players",
            "RoundRepository $rounds",
            "ScoreService $scores",
            "LeaderboardService $leaderboard",
            "NotificationService $notifications",
            "AuditService $audit",
        ],
    )
    facts.methods.append(ctor)

    findings = TooManyDependenciesRule(RuleConfig()).analyze(facts)
    assert any(f.rule_id == "too-many-dependencies" for f in findings)


def test_god_class_still_flags_large_non_coordinator_service_in_layered_backend():
    facts = Facts(project_path=".")
    facts.project_context.backend_structure_mode = "layered"
    facts.classes.append(
        ClassInfo(
            name="BloatedMatchService",
            fqcn="App\\Services\\Analytics\\BloatedMatchService",
            file_path="app/Services/Analytics/BloatedMatchService.php",
            file_hash="svc",
            line_start=1,
            line_end=260,
        )
    )
    for index in range(22):
        facts.methods.append(
            MethodInfo(
                name=f"method{index}",
                class_name="BloatedMatchService",
                class_fqcn="App\\Services\\Analytics\\BloatedMatchService",
                method_fqn=f"App\\Services\\Analytics\\BloatedMatchService::method{index}",
                file_path="app/Services/Analytics/BloatedMatchService.php",
                file_hash="svc",
                line_start=10 + (index * 5),
                line_end=13 + (index * 5),
                loc=4,
                visibility="public",
            )
        )

    findings = GodClassRule(RuleConfig(thresholds={"max_loc": 200, "max_methods": 20})).analyze(facts)
    assert any(f.rule_id == "god-class" for f in findings)


def test_large_component_still_flags_uncomposed_large_page():
    facts = Facts(project_path=".")
    facts.project_context.react_structure_mode = "hybrid"
    facts.react_components.append(
        ReactComponentInfo(
            name="OversizedDashboard",
            file_path="resources/js/Pages/Admin/OversizedDashboard.tsx",
            file_hash="ui",
            line_start=1,
            line_end=420,
            loc=420,
            imports=[],
        )
    )

    findings = LargeComponentRule(RuleConfig(thresholds={"max_loc": 200})).run(
        facts, project_type="laravel_inertia_react"
    ).findings
    assert any(f.rule_id == "large-react-component" for f in findings)


def test_no_inline_services_still_flags_multiple_strong_helpers_even_with_extracted_imports():
    facts = Facts(project_path=".")
    facts.react_components.append(
        ReactComponentInfo(
            name="Management",
            file_path="resources/js/Pages/Admin/Management.tsx",
            file_hash="ui",
            line_start=1,
            line_end=180,
            loc=180,
            has_inline_helper_fns=True,
            inline_helper_names=["fetchCategories", "saveCategory", "persistWord"],
        )
    )
    facts._frontend_symbol_graph = {
        "files": {
            "resources/js/Pages/Admin/Management.tsx": {
                "imports": ["./utils/formatTimer", "@/hooks/useAdminDashboardState", "@/Components/Game/ScorePanel"]
            }
        }
    }

    findings = NoInlineServicesRule(RuleConfig()).run(facts, project_type="laravel_inertia_react").findings
    assert any(f.rule_id == "no-inline-services" for f in findings)


def test_react_project_structure_still_flags_chaotic_hybrid_layout():
    facts = Facts(project_path=".")
    facts.project_context.react_structure_mode = "hybrid"
    facts.project_context.react_shared_roots = ["hooks", "components", "services"]
    facts.files = [
        "resources/js/hooks/useAuth.ts",
        "resources/js/services/game/gameService.ts",
        "resources/js/components/Game/helpers/gameHelper.ts",
        "resources/js/helpers/formatHelper.ts",
        "resources/js/pages/Game/utils/gameUtils.ts",
        "resources/js/pages/Game/services/sessionService.ts",
        "resources/js/pages/Admin/services/adminService.ts",
        "resources/js/pages/Admin/Dashboard.tsx",
        "resources/js/pages/Game/Portal.tsx",
        "resources/js/usePortal.ts",
        "resources/js/portalService.ts",
    ]

    findings = ReactProjectStructureConsistencyRule(RuleConfig()).run(facts).findings
    assert any(f.rule_id == "react-project-structure-consistency" for f in findings)
