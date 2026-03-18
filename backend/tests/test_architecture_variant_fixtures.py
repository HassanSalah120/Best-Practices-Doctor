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


def _run_fixture(fixture_path: Path, fixture_name: str, rule_ids: list[str]):
    info, facts, metrics = _build_fixture(fixture_path, fixture_name)
    engine = create_engine(ruleset=_ruleset_for(rule_ids), selected_rules=rule_ids)
    result = engine.run(facts, metrics=metrics, project_type=info.project_type.value)
    return info, facts, metrics, result


def test_layered_backend_without_dtos_is_accepted(fixture_path: Path):
    info, facts, _, result = _run_fixture(
        fixture_path,
        "laravel-layered-no-dto-mini",
        ["controller-business-logic", "service-extraction", "too-many-dependencies", "god-class"],
    )

    assert info.project_type.value.startswith("laravel")
    assert facts.project_context.backend_structure_mode == "layered"
    assert {"actions", "services", "repositories", "providers"}.issubset(set(facts.project_context.backend_layers))
    assert result.findings == [], [f"{finding.rule_id}:{finding.file}" for finding in result.findings]


def test_layered_backend_with_actions_but_no_repositories_is_accepted(fixture_path: Path):
    _, facts, _, result = _run_fixture(
        fixture_path,
        "laravel-layered-actions-no-repository-mini",
        ["controller-business-logic", "service-extraction"],
    )

    assert facts.project_context.backend_structure_mode == "layered"
    assert {"actions", "services", "contracts", "providers"}.issubset(set(facts.project_context.backend_layers))
    assert result.findings == []


def test_bounded_coordinator_fixture_is_accepted_without_overfitting(fixture_path: Path):
    _, facts, _, result = _run_fixture(
        fixture_path,
        "laravel-coordinator-bounded-mini",
        ["too-many-dependencies", "god-class"],
    )

    assert facts.project_context.backend_structure_mode == "layered"
    assert result.findings == []


def test_composed_page_alt_layout_fixture_is_accepted(fixture_path: Path):
    _, facts, _, result = _run_fixture(
        fixture_path,
        "react-composed-page-alt-layout-mini",
        ["large-react-component", "no-inline-services", "react-project-structure-consistency"],
    )

    assert facts.project_context.react_structure_mode == "hybrid"
    assert result.findings == []


def test_hybrid_frontend_alt_naming_fixture_is_accepted_and_profiled(fixture_path: Path):
    _, facts, _, result = _run_fixture(
        fixture_path,
        "react-hybrid-alt-naming-mini",
        ["react-project-structure-consistency"],
    )

    rule = ReactProjectStructureConsistencyRule(RuleConfig())
    files = rule._collect_frontend_files(facts)
    candidates = [c for path in files if (c := rule._build_candidate(path))]
    shared_roots = rule._shared_roots(facts)
    pattern = rule._context_pattern(facts) or rule._infer_pattern(candidates, shared_roots)
    scale = rule._scale(files, candidates, facts)
    importers = rule._resolve_importers(facts, files)
    profile = rule._analysis_profile(
        candidates=candidates,
        pattern=pattern,
        scale=scale,
        shared_roots=shared_roots,
        placement=rule._find_placement_issues(candidates, pattern, scale, shared_roots),
        buried=rule._find_buried_shared(candidates, importers, shared_roots),
        single_domain_global=rule._find_single_domain_global(candidates, importers, pattern, scale, shared_roots),
        duplicates=rule._find_duplicates(candidates, scale, shared_roots),
    )

    assert facts.project_context.react_structure_mode == "hybrid"
    assert profile["pattern"] == "hybrid"
    assert profile["placement_count"] == 0
    assert result.findings == []


def test_layered_backend_near_miss_fixture_still_flags_real_controller_logic(fixture_path: Path):
    _, _, _, result = _run_fixture(
        fixture_path,
        "laravel-layered-near-miss-mini",
        ["controller-business-logic", "service-extraction"],
    )

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "controller-business-logic" in rule_ids
    assert "service-extraction" in rule_ids
    assert all("decision_profile" in finding.metadata or "decision_reasons" in finding.metadata for finding in result.findings)


def test_hybrid_frontend_near_miss_fixture_still_flags_structure_drift(fixture_path: Path):
    _, _, _, result = _run_fixture(
        fixture_path,
        "react-hybrid-near-miss-mini",
        ["react-project-structure-consistency"],
    )

    assert any(f.rule_id == "react-project-structure-consistency" for f in result.findings)
    finding = next(f for f in result.findings if f.rule_id == "react-project-structure-consistency")
    assert finding.metadata["decision_profile"]["pattern"] in {"hybrid", "mixed-chaotic"}
    assert finding.metadata["decision_profile"]["placement_count"] >= 1


def test_controller_business_logic_accepts_boundary_thin_orchestration():
    facts = Facts(project_path=".")
    facts.project_context.backend_structure_mode = "layered"
    facts.project_context.backend_architecture_profile = "layered"
    facts.project_context.backend_profile_confidence = 0.91
    facts.project_context.backend_profile_confidence_kind = "structural"
    facts.project_context.backend_profile_signals = ["framework=laravel", "profile=layered", "layers=actions,services,repositories,providers"]
    facts.project_context.backend_layers = ["actions", "services", "repositories", "providers"]
    controller = ClassInfo(
        name="RoundController",
        fqcn="App\\Http\\Controllers\\RoundController",
        file_path="app/Http/Controllers/RoundController.php",
        file_hash="ctrl",
        line_start=1,
        line_end=120,
    )
    method = MethodInfo(
        name="store",
        class_name=controller.name,
        class_fqcn=controller.fqcn,
        method_fqn=f"{controller.fqcn}::store",
        file_path=controller.file_path,
        file_hash="ctrl",
        line_start=20,
        line_end=88,
        loc=69,
        call_sites=[
            "$request->validated()",
            "$dto = new PublishRoundDTO($request->validated())",
            "$this->publishRound->execute($dto)",
            "return back()->with('status', 'ok')",
        ],
    )
    facts.controllers.append(controller)
    facts.methods.append(method)
    metrics = {
        method.method_fqn: MethodMetrics(
        method_fqn=method.method_fqn,
        file_path=method.file_path,
        cyclomatic_complexity=6,
        conditional_count=2,
        validation_count=1,
        has_business_logic=True,
        business_logic_confidence=0.78,
    )
    }

    rule = ControllerBusinessLogicRule(RuleConfig())
    profile = rule._decision_profile(
        method,
        metrics[method.method_fqn],
        set(),
        "layered",
        True,
        False,
        profile_confidence=0.91,
        profile_confidence_kind="structural",
        profile_signals=facts.project_context.backend_profile_signals,
    )

    assert profile["suppressed_as_thin_orchestration"] is True
    assert profile["decision"] == "suppress"
    assert profile["suppression_reason"] == "thin-orchestration"
    assert profile["profile_confidence_kind"] == "structural"
    assert rule.analyze(facts, metrics) == []


def test_service_extraction_accepts_boundary_layered_orchestration():
    facts = Facts(project_path=".")
    facts.project_context.backend_structure_mode = "layered"
    facts.project_context.backend_architecture_profile = "layered"
    facts.project_context.backend_profile_confidence = 0.9
    facts.project_context.backend_profile_confidence_kind = "structural"
    facts.project_context.backend_profile_signals = ["framework=laravel", "profile=layered"]
    controller = ClassInfo(
        name="RoundController",
        fqcn="App\\Http\\Controllers\\RoundController",
        file_path="app/Http/Controllers/RoundController.php",
        file_hash="ctrl",
        line_start=1,
        line_end=110,
    )
    constructor = MethodInfo(
        name="__construct",
        class_name=controller.name,
        class_fqcn=controller.fqcn,
        method_fqn=f"{controller.fqcn}::__construct",
        file_path=controller.file_path,
        file_hash="ctrl",
        line_start=5,
        line_end=12,
        loc=8,
        parameters=["PublishRoundAction $publishRound", "RoundRepository $rounds"],
    )
    method = MethodInfo(
        name="store",
        class_name=controller.name,
        class_fqcn=controller.fqcn,
        method_fqn=f"{controller.fqcn}::store",
        file_path=controller.file_path,
        file_hash="ctrl",
        line_start=15,
        line_end=68,
        loc=54,
        call_sites=[
            "$request->validated()",
            "$dto = new PublishRoundDTO($request->validated())",
            "$this->publishRound->execute($dto)",
            "return back()->with('status', 'ok')",
        ],
    )
    facts.controllers.append(controller)
    facts.methods.extend([constructor, method])
    metrics = {
        method.method_fqn: MethodMetrics(
            method_fqn=method.method_fqn,
            file_path=method.file_path,
            cyclomatic_complexity=6,
            conditional_count=2,
            has_business_logic=True,
            business_logic_confidence=0.7,
        )
    }

    rule = ServiceExtractionRule(RuleConfig())
    profile = rule._decision_profile(
        method,
        facts=facts,
        metrics=metrics,
        architecture_profile="layered",
        has_service_injection=True,
        uses_repository_pattern=True,
        profile_confidence=0.9,
        profile_confidence_kind="structural",
        profile_signals=facts.project_context.backend_profile_signals,
    )

    assert profile["suppression_checks"]["layered_orchestration"] is True
    assert profile["decision"] == "suppress"
    assert profile["suppression_reason"] == "thin-profile-orchestration"
    assert profile["profile_confidence_kind"] == "structural"
    assert rule.analyze(facts, metrics) == []


def test_too_many_dependencies_accepts_bounded_coordinator_shape():
    facts = Facts(project_path=".")
    facts.project_context.backend_structure_mode = "layered"
    ctor = MethodInfo(
        name="__construct",
        class_name="RealtimeWorkflowCoordinator",
        class_fqcn="App\\Services\\Realtime\\RealtimeWorkflowCoordinator",
        method_fqn="App\\Services\\Realtime\\RealtimeWorkflowCoordinator::__construct",
        file_path="app/Services/Realtime/RealtimeWorkflowCoordinator.php",
        file_hash="svc",
        line_start=10,
        line_end=22,
        loc=13,
        parameters=[
            "QueueDriverInterface $queueDriver",
            "ConnectionGateway $connections",
            "SessionVisibilityService $visibility",
            "TokenIssuer $tokenIssuer",
            "CommandDispatcher $commands",
            "PresencePublisher $presencePublisher",
            "MetricsStore $metricsStore",
            "DispatchPresenceSnapshotAction $snapshot",
        ],
    )
    facts.methods.append(ctor)

    rule = TooManyDependenciesRule(RuleConfig())
    profile = rule._dependency_profile(ctor, "layered")

    assert profile["service_orchestrator_shape"] is True
    assert rule.analyze(facts) == []


def test_god_class_accepts_bounded_coordinator_near_threshold():
    facts = Facts(project_path=".")
    facts.project_context.backend_structure_mode = "layered"
    cls = ClassInfo(
        name="RealtimeWorkflowCoordinator",
        fqcn="App\\Services\\Realtime\\RealtimeWorkflowCoordinator",
        file_path="app/Services/Realtime/RealtimeWorkflowCoordinator.php",
        file_hash="svc",
        line_start=1,
        line_end=340,
    )
    ctor = MethodInfo(
        name="__construct",
        class_name=cls.name,
        class_fqcn=cls.fqcn,
        method_fqn=f"{cls.fqcn}::__construct",
        file_path=cls.file_path,
        file_hash="svc",
        line_start=10,
        line_end=24,
        loc=15,
        parameters=[
            "QueueDriverInterface $queueDriver",
            "ConnectionGateway $connections",
            "SessionVisibilityService $visibility",
            "TokenIssuer $tokenIssuer",
            "CommandDispatcher $commands",
            "PresencePublisher $presencePublisher",
            "MetricsStore $metricsStore",
        ],
    )
    facts.classes.append(cls)
    facts.methods.append(ctor)
    for index in range(14):
        facts.methods.append(
            MethodInfo(
                name=f"step{index}",
                class_name=cls.name,
                class_fqcn=cls.fqcn,
                method_fqn=f"{cls.fqcn}::step{index}",
                file_path=cls.file_path,
                file_hash="svc",
                line_start=30 + (index * 10),
                line_end=34 + (index * 10),
                loc=5,
                visibility="public",
            )
        )

    rule = GodClassRule(RuleConfig())
    public_like = [m for m in facts.methods if m.class_fqcn == cls.fqcn and m.name != "__construct"]

    assert rule._is_service_coordinator(cls, public_like, facts.methods, "layered") is True
    assert rule.analyze(facts) == []


def test_too_many_dependencies_finding_includes_profile_explainability():
    facts = Facts(project_path=".")
    facts.project_context.backend_architecture_profile = "mvc"
    facts.project_context.backend_profile_confidence = 0.87
    facts.project_context.backend_profile_confidence_kind = "structural"
    facts.project_context.backend_profile_signals = ["framework=laravel", "profile=mvc", "layers=requests"]
    ctor = MethodInfo(
        name="__construct",
        class_name="AnalyticsService",
        class_fqcn="App\\Services\\AnalyticsService",
        method_fqn="App\\Services\\AnalyticsService::__construct",
        file_path="app/Services/AnalyticsService.php",
        file_hash="svc",
        line_start=10,
        line_end=22,
        loc=13,
        parameters=[
            "LoggerInterface $logger",
            "MailerInterface $mailer",
            "CacheStore $cache",
            "MetricsRepository $metrics",
            "ExportGateway $exports",
            "NotificationService $notifications",
            "AuditTrailService $auditTrail",
        ],
    )
    facts.methods.append(ctor)

    findings = TooManyDependenciesRule(RuleConfig()).analyze(facts)

    assert len(findings) == 1
    decision = findings[0].metadata["decision_profile"]
    assert decision["architecture_profile"] == "mvc"
    assert decision["profile_confidence_kind"] == "structural"
    assert decision["profile_signals"]
    assert decision["decision"] == "emit"
    assert decision["decision_summary"]
    assert findings[0].confidence > 0


def test_god_class_finding_includes_profile_explainability():
    facts = Facts(project_path=".")
    facts.project_context.backend_architecture_profile = "layered"
    facts.project_context.backend_profile_confidence = 0.9
    facts.project_context.backend_profile_confidence_kind = "structural"
    facts.project_context.backend_profile_signals = ["framework=laravel", "profile=layered", "layers=actions,services,repositories"]
    cls = ClassInfo(
        name="BillingService",
        fqcn="App\\Services\\BillingService",
        file_path="app/Services/BillingService.php",
        file_hash="svc",
        line_start=1,
        line_end=390,
    )
    facts.classes.append(cls)
    ctor = MethodInfo(
        name="__construct",
        class_name=cls.name,
        class_fqcn=cls.fqcn,
        method_fqn=f"{cls.fqcn}::__construct",
        file_path=cls.file_path,
        file_hash="svc",
        line_start=5,
        line_end=16,
        loc=12,
        parameters=[
            "InvoiceGateway $invoices",
            "PaymentGateway $payments",
            "LedgerRepository $ledgers",
            "TaxCalculator $taxes",
            "DiscountService $discounts",
            "ReceiptService $receipts",
        ],
    )
    facts.methods.append(ctor)
    for index in range(21):
        facts.methods.append(
            MethodInfo(
                name=f"step{index}",
                class_name=cls.name,
                class_fqcn=cls.fqcn,
                method_fqn=f"{cls.fqcn}::step{index}",
                file_path=cls.file_path,
                file_hash="svc",
                line_start=20 + (index * 5),
                line_end=24 + (index * 5),
                loc=5,
                visibility="public",
            )
        )

    findings = GodClassRule(RuleConfig()).analyze(facts, metrics={})

    assert len(findings) == 1
    decision = findings[0].metadata["decision_profile"]
    assert decision["architecture_profile"] == "layered"
    assert decision["profile_confidence_kind"] == "structural"
    assert decision["profile_signals"]
    assert decision["decision"] == "emit"
    assert decision["decision_summary"]
    assert findings[0].confidence > 0


def test_large_component_accepts_composed_screen_outside_pages_root():
    facts = Facts(project_path=".")
    component = ReactComponentInfo(
        name="PortalScreen",
        file_path="resources/js/screens/live/PortalScreen.tsx",
        file_hash="ui",
        line_start=1,
        line_end=340,
        loc=340,
        imports=[],
    )
    facts.react_components.append(component)
    facts._frontend_symbol_graph = {
        "files": {
            "resources/js/screens/live/PortalScreen.tsx": {
                "imports": [
                    "../../composables/usePortalScreenState",
                    "../../widgets/game/StagePanel",
                    "../../widgets/game/ResultsDrawer",
                    "./lib/portalTimer",
                ]
            }
        }
    }

    rule = LargeComponentRule(RuleConfig(thresholds={"max_loc": 200}))
    profile = rule._component_profile(component, 200, facts)

    assert profile["is_feature_shell"] is True
    assert profile["threshold"] >= 340
    assert rule.run(facts, project_type="laravel_inertia_react").findings == []


def test_no_inline_services_accepts_single_local_glue_helper_in_screen_shell():
    facts = Facts(project_path=".")
    component = ReactComponentInfo(
        name="PortalScreen",
        file_path="resources/js/screens/live/PortalScreen.tsx",
        file_hash="ui",
        line_start=1,
        line_end=220,
        loc=220,
        has_inline_helper_fns=True,
        inline_helper_names=["submitRound"],
    )
    facts.react_components.append(component)
    facts._frontend_symbol_graph = {
        "files": {
            "resources/js/screens/live/PortalScreen.tsx": {
                "imports": [
                    "../../composables/usePortalScreenState",
                    "../../widgets/game/StagePanel",
                    "./lib/portalTimer",
                ]
            }
        }
    }

    rule = NoInlineServicesRule(RuleConfig())
    profile = rule._helper_profile(component, ["submitRound"], facts)

    assert profile["suppressed_as_local_glue"] is True
    assert rule.run(facts, project_type="laravel_inertia_react").findings == []
