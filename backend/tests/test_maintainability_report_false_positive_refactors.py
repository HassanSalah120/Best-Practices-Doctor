from __future__ import annotations

from core.pipeline.cache_signatures import implementation_signature
from core.ruleset import RuleConfig
from rules.laravel.api_resource_usage import ApiResourceUsageRule
from rules.laravel.controller_query_direct import ControllerQueryDirectRule
from rules.laravel.controller_business_logic import ControllerBusinessLogicRule
from rules.laravel.dto_suggestion import DtoSuggestionRule
from rules.laravel.hardcoded_magic_strings import HardcodedMagicStringsRule
from rules.laravel.laravel_naming_conventions import LaravelNamingConventionsRule
from rules.laravel.missing_feature_flag_pattern import MissingFeatureFlagPatternRule
from rules.laravel.model_cross_model_query import ModelCrossModelQueryRule
from rules.laravel.public_api_versioning_missing import PublicApiVersioningMissingRule
from rules.php.circular_dependency import CircularDependencyRule
from rules.php.dry_violation import DryViolationRule
from rules.php.high_coupling_class import HighCouplingClassRule
from rules.php.too_many_dependencies import TooManyDependenciesRule
from schemas.facts import AssocArrayLiteral, ClassInfo, DuplicateBlock, Facts, MethodInfo, QueryUsage, RouteInfo
from schemas.metrics import MethodMetrics


def _class(name: str, namespace: str = "App\\Services") -> ClassInfo:
    relative_namespace = namespace.removeprefix("App\\").replace("\\", "/")
    return ClassInfo(
        name=name,
        fqcn=f"{namespace}\\{name}",
        file_path=f"app/{relative_namespace}/{name}.php",
        file_hash=name.lower(),
        line_start=1,
        line_end=100,
    )


def test_report_data_transfer_constructors_are_not_counted_as_dependencies() -> None:
    facts = Facts(project_path=".")
    cases = {
        "BoardTileData": 11,
        "CategoryData": 9,
        "CreateUserPayload": 8,
        "LeaderboardEntry": 6,
        "ScoringEntry": 6,
        "SessionData": 21,
        "StartCategoryConfig": 8,
        "TeamEntryData": 6,
        "UpdateUserPayload": 8,
    }
    for name, count in cases.items():
        facts.methods.append(
            MethodInfo(
                name="__construct",
                class_name=name,
                class_fqcn=f"App\\DataTransfer\\Lms\\{name}",
                file_path=f"app/DataTransfer/Lms/{name}.php",
                file_hash=name,
                parameters=[f"public readonly string $field{i}" for i in range(count)],
            ),
        )

    assert TooManyDependenciesRule(RuleConfig()).analyze(facts) == []

    facts.methods.append(
        MethodInfo(
            name="__construct",
            class_name="AnalyticsService",
            class_fqcn="App\\Services\\AnalyticsService",
            file_path="app/Services/AnalyticsService.php",
            file_hash="workflow",
            parameters=[f"Dependency{i} $dependency{i}" for i in range(6)],
        ),
    )
    assert len(TooManyDependenciesRule(RuleConfig()).analyze(facts)) == 1


def test_report_protocol_json_payloads_do_not_imply_api_resources() -> None:
    rule = ApiResourceUsageRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
    namespace App\\Http\\Controllers\\Api;
    class LmsWebsocketController {
        public function auth() {
            return response()->json(['broadcasts' => $this->wsService->handleAuth($user)]);
        }
        public function leaderboard() {
            return response()->json(['leaderboard' => $payload]);
        }
    }
    """
    assert rule.analyze_regex("app/Http/Controllers/Api/LmsWebsocketController.php", content, facts) == []

    model_payload = "class UserApiController { function index() { return ['data' => User::query()->paginate()]; } }"
    assert len(rule.analyze_regex("app/Http/Controllers/Api/UserApiController.php", model_payload, facts)) == 1


def test_report_cache_read_is_not_a_controller_database_query() -> None:
    facts = Facts(project_path=".")
    controller = _class("HealthController", "App\\Http\\Controllers")
    facts.controllers.append(controller)
    facts.methods.append(
        MethodInfo(
            name="checkCache",
            class_name=controller.name,
            class_fqcn=controller.fqcn,
            file_path=controller.file_path,
            file_hash="health",
        ),
    )
    facts.queries.append(
        QueryUsage(
            file_path=controller.file_path,
            line_number=51,
            method_name="checkCache",
            model="Cache",
            method_chain="get",
        ),
    )
    assert ControllerQueryDirectRule(RuleConfig()).analyze(facts) == []


def test_delegated_websocket_command_is_protocol_orchestration() -> None:
    facts = Facts(project_path=".")
    facts.project_context.backend_architecture_profile = "layered"
    controller = _class("LmsWebsocketController", "App\\Http\\Controllers\\Lms")
    method = MethodInfo(
        name="command",
        class_name=controller.name,
        class_fqcn=controller.fqcn,
        file_path=controller.file_path,
        file_hash="websocket",
        line_start=22,
        line_end=88,
        loc=67,
        call_sites=["$this->wsService->handle($validated)", "response()->json($result)"],
    )
    facts.controllers.append(controller)
    facts.methods.append(method)
    metrics = {
        method.method_fqn: MethodMetrics(
            method_fqn=method.method_fqn,
            file_path=method.file_path,
            cyclomatic_complexity=10,
            conditional_count=9,
            query_count=2,
            validation_count=1,
            loop_count=0,
            has_business_logic=True,
            business_logic_confidence=1.0,
        ),
    }
    assert ControllerBusinessLogicRule(RuleConfig()).analyze(facts, metrics) == []


def test_report_self_queries_are_not_cross_model_queries() -> None:
    facts = Facts(project_path=".")
    model = _class("GameSession", "App\\Models")
    facts.models.append(model)
    facts.methods.append(
        MethodInfo(
            name="resolveMeta",
            class_name=model.name,
            class_fqcn=model.fqcn,
            file_path=model.file_path,
            file_hash="game",
        ),
    )
    facts.queries.append(
        QueryUsage(
            file_path=model.file_path,
            line_number=94,
            method_name="resolveMeta",
            model="GameSession",
            method_chain="query->from->leftJoin->first",
        ),
    )
    assert ModelCrossModelQueryRule(RuleConfig()).analyze(facts) == []


def test_eloquent_relationship_graph_is_not_a_circular_dependency() -> None:
    facts = Facts(project_path=".")
    user = _class("User", "App\\Models")
    session = _class("GameSession", "App\\Models")
    facts.classes.extend([user, session])
    facts.models.extend([user, session])
    facts.methods.extend(
        [
            MethodInfo(
                name="sessions",
                class_name=user.name,
                class_fqcn=user.fqcn,
                file_path=user.file_path,
                file_hash="user",
                call_sites=["$this->hasMany(GameSession::class)"],
            ),
            MethodInfo(
                name="user",
                class_name=session.name,
                class_fqcn=session.fqcn,
                file_path=session.file_path,
                file_hash="session",
                call_sites=["$this->belongsTo(User::class)"],
            ),
        ],
    )
    assert CircularDependencyRule(RuleConfig()).analyze(facts) == []


def _coupling_facts(*, behavioral: int, passive: int) -> Facts:
    facts = Facts(project_path=".")
    owner = _class("LmsStateBuilder", "App\\ReadModels")
    behavioral_classes = [_class(f"Model{i}", "App\\Models") for i in range(behavioral)]
    passive_classes = [_class(f"Projection{i}Data", "App\\DataTransfer") for i in range(passive)]
    facts.classes.extend([owner, *behavioral_classes, *passive_classes])
    facts.methods.append(
        MethodInfo(
            name="build",
            class_name=owner.name,
            class_fqcn=owner.fqcn,
            file_path=owner.file_path,
            file_hash="builder",
            instantiations=[item.name for item in [*behavioral_classes, *passive_classes]],
        ),
    )
    return facts


def test_high_coupling_counts_behavioral_collaborators_not_data_contracts() -> None:
    rule = HighCouplingClassRule(RuleConfig(thresholds={"max_outgoing": 12}))
    assert rule.analyze(_coupling_facts(behavioral=12, passive=5)) == []
    findings = rule.analyze(_coupling_facts(behavioral=13, passive=4))
    assert len(findings) == 1
    assert "behavioral_dependencies=13" in findings[0].evidence_signals


def test_report_controller_boundary_boilerplate_is_not_a_dry_violation() -> None:
    facts = Facts(project_path=".")
    facts.duplicates.append(
        DuplicateBlock(
            hash="report",
            token_count=75,
            occurrences=[
                ("app/Http/Controllers/Lms/CategoriesController.php", 59, 65),
                ("app/Http/Controllers/Lms/UsersController.php", 40, 46),
                ("app/Http/Controllers/Lms/UsersController.php", 80, 86),
            ],
            code_snippet=(
                "$idRequest = app(IdRequest::class);\n"
                "abort_unless($idRequest->authorize(), 403);\n"
                "$validated = $request->validate($idRequest->rules());\n"
                "$id = $this->service->duplicate($validated);"
            ),
        ),
    )
    assert DryViolationRule(RuleConfig()).analyze(facts) == []


def test_series_and_alias_are_singular_domain_nouns() -> None:
    rule = LaravelNamingConventionsRule(RuleConfig())
    content = """
    class CategoryAnswerAlias extends Model {}
    class CategorySeries extends Model {
        public function series(): BelongsTo { return $this->belongsTo(Series::class); }
    }
    class Series extends Model {}
    class GameSession extends Model {
        public function series(): BelongsTo { return $this->belongsTo(Series::class); }
    }
    class SeriesStanding extends Model {
        public function series(): BelongsTo { return $this->belongsTo(Series::class); }
    }
    """
    assert rule.analyze_regex("app/Models/DomainModels.php", content, Facts(project_path=".")) == []


def test_magic_string_rule_requires_repeated_domain_decisions() -> None:
    rule = HardcodedMagicStringsRule(RuleConfig())
    labels = "return ['admin' => $admin, 'admin' => $fallback, 'admin' => $meta];"
    assert rule.analyze_regex("app/ReadModels/StateBuilder.php", labels, Facts(project_path=".")) == []

    decisions = """
    if ($role === 'admin') {}
    $query->where('role', 'admin');
    $state = match ($role) { 'admin' => 1 };
    """
    assert len(rule.analyze_regex("app/Services/AccessService.php", decisions, Facts(project_path="."))) == 1


def _dto_facts(target: str) -> Facts:
    facts = Facts(project_path=".")
    facts.project_context.backend_team_expectations = {
        "dto_data_objects_preferred": {"enabled": True, "confidence": 0.9, "evidence": ["data_object_classes=12"]},
    }
    facts.assoc_arrays.append(
        AssocArrayLiteral(
            file_path="app/Actions/Lms/StartCategoryAction.php",
            line_number=222,
            method_name="persistSession",
            class_fqcn="App\\Actions\\Lms\\StartCategoryAction",
            key_count=10,
            used_as="argument",
            target=target,
        ),
    )
    return facts


def test_persistence_attribute_arrays_do_not_trigger_dto_suggestions() -> None:
    rule = DtoSuggestionRule(RuleConfig())
    assert rule.analyze(_dto_facts("GameSession::insertGetId")) == []
    assert len(rule.analyze(_dto_facts("$this->gateway->send"))) == 1


def test_unversioned_route_needs_public_contract_evidence() -> None:
    rule = PublicApiVersioningMissingRule(RuleConfig())
    internal = Facts(project_path=".")
    internal.routes.append(
        RouteInfo(method="POST", uri="api/ws/command", file_path="routes/lms.php", line_number=75),
    )
    assert rule.analyze(internal) == []

    established = Facts(project_path=".")
    established.routes.extend(
        [
            RouteInfo(method="GET", uri="api/v1/users", file_path="routes/api.php", line_number=1),
            RouteInfo(method="GET", uri="api/reports", file_path="routes/api.php", line_number=2),
        ],
    )
    assert len(rule.analyze(established)) == 1


def test_feature_flag_absence_is_opt_in_not_route_count_inference(tmp_path) -> None:
    facts = Facts(project_path=str(tmp_path))
    facts.routes = [
        RouteInfo(method="GET", uri=f"page/{index}", file_path="routes/web.php", line_number=index + 1)
        for index in range(47)
    ]
    assert MissingFeatureFlagPatternRule(RuleConfig()).analyze(facts) == []
    opted_in = MissingFeatureFlagPatternRule(
        RuleConfig(thresholds={"require_explicit_adoption_signal": False}),
    )
    finding = opted_in.analyze(facts)
    assert len(finding) == 1
    assert finding[0].file == "."


def test_rule_implementation_signature_changes_with_source() -> None:
    class First:
        def value(self) -> int:
            return 1

    class Second:
        def value(self) -> int:
            return 2

    assert implementation_signature([First]) != implementation_signature([Second])
