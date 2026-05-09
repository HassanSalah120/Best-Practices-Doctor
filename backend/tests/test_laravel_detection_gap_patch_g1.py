from __future__ import annotations

from pathlib import Path

from analysis.facts_builder import FactsBuilder
from analysis.metrics_analyzer import MetricsAnalyzer
from core.context_profiles import ContextProfileMatrix
from core.detector import ProjectDetector
from core.rule_engine import ALL_RULES, create_engine
from core.ruleset import RuleConfig, Ruleset
from rules.laravel.action_class_naming_consistency import ActionClassNamingConsistencyRule
from rules.laravel.controller_index_filter_duplication import ControllerIndexFilterDuplicationRule
from rules.laravel.model_cross_model_query import ModelCrossModelQueryRule
from schemas.facts import ClassInfo, Facts, MethodInfo, QueryUsage


G1_RULES = [
    "controller-index-filter-duplication",
    "model-cross-model-query",
    "action-class-naming-consistency",
]


def _ruleset_for(rule_ids: list[str]) -> Ruleset:
    rules = {rule_id: RuleConfig(enabled=False) for rule_id in ALL_RULES.keys()}
    for rule_id in rule_ids:
        rules[rule_id] = RuleConfig(enabled=True)
    return Ruleset(rules=rules, name="strict")


def _controller(path: str, name: str) -> ClassInfo:
    return ClassInfo(
        name=name,
        fqcn=f"App\\Http\\Controllers\\Admin\\{name}",
        file_path=path,
        file_hash=f"{name}-hash",
        line_start=1,
        line_end=120,
    )


def _model(path: str, name: str) -> ClassInfo:
    return ClassInfo(
        name=name,
        fqcn=f"App\\Models\\{name}",
        file_path=path,
        file_hash=f"{name}-hash",
        line_start=1,
        line_end=120,
    )


def test_controller_index_filter_duplication_valid_near_invalid():
    rule = ControllerIndexFilterDuplicationRule(
        RuleConfig(thresholds={"max_findings_per_file": 3, "min_confidence": 0.74})
    )

    valid = Facts(project_path=".")
    valid.controllers.extend(
        [
            _controller("app/Http/Controllers/Admin/TopicController.php", "TopicController"),
            _controller("app/Http/Controllers/Admin/UserController.php", "UserController"),
        ]
    )
    valid.methods.extend(
        [
            MethodInfo(
                name="index",
                class_name="TopicController",
                class_fqcn="App\\Http\\Controllers\\Admin\\TopicController",
                file_path="app/Http/Controllers/Admin/TopicController.php",
                file_hash="topic",
                line_start=20,
                line_end=55,
                call_sites=["$this->resolveIndexFilters($request)"],
            ),
            MethodInfo(
                name="index",
                class_name="UserController",
                class_fqcn="App\\Http\\Controllers\\Admin\\UserController",
                file_path="app/Http/Controllers/Admin/UserController.php",
                file_hash="user",
                line_start=20,
                line_end=60,
                call_sites=["$request->string('status')->value()"],
            ),
        ]
    )
    assert rule.analyze(valid) == []

    near_miss = Facts(project_path=".")
    near_miss.controllers.extend(
        [
            _controller("app/Http/Controllers/Admin/AuditController.php", "AuditController"),
            _controller("app/Http/Controllers/Admin/LogsController.php", "LogsController"),
        ]
    )
    near_miss.methods.extend(
        [
            MethodInfo(
                name="index",
                class_name="AuditController",
                class_fqcn="App\\Http\\Controllers\\Admin\\AuditController",
                file_path="app/Http/Controllers/Admin/AuditController.php",
                file_hash="audit",
                line_start=12,
                line_end=38,
                call_sites=["$filters->get('status')", "$filters->get('search')"],
            ),
            MethodInfo(
                name="index",
                class_name="LogsController",
                class_fqcn="App\\Http\\Controllers\\Admin\\LogsController",
                file_path="app/Http/Controllers/Admin/LogsController.php",
                file_hash="logs",
                line_start=12,
                line_end=38,
                call_sites=["$filters->get('status')", "$filters->get('search')"],
            ),
        ]
    )
    assert rule.analyze(near_miss) == []

    invalid = Facts(project_path=".")
    invalid.controllers.extend(
        [
            _controller("app/Http/Controllers/Admin/SubmissionManagementController.php", "SubmissionManagementController"),
            _controller("app/Http/Controllers/Admin/UserManagementController.php", "UserManagementController"),
        ]
    )
    invalid.methods.extend(
        [
            MethodInfo(
                name="index",
                class_name="SubmissionManagementController",
                class_fqcn="App\\Http\\Controllers\\Admin\\SubmissionManagementController",
                file_path="app/Http/Controllers/Admin/SubmissionManagementController.php",
                file_hash="sub",
                line_start=22,
                line_end=70,
                call_sites=[
                    "$request->string('status')->value()",
                    "$request->string('q')->trim()->value()",
                ],
            ),
            MethodInfo(
                name="index",
                class_name="UserManagementController",
                class_fqcn="App\\Http\\Controllers\\Admin\\UserManagementController",
                file_path="app/Http/Controllers/Admin/UserManagementController.php",
                file_hash="usr",
                line_start=25,
                line_end=68,
                call_sites=[
                    "$request->string('status')->value()",
                    "$request->string('q')->trim()->value()",
                ],
            ),
        ]
    )
    findings = rule.analyze(invalid)
    assert len(findings) == 2
    assert all(f.rule_id == "controller-index-filter-duplication" for f in findings)


def test_model_cross_model_query_valid_near_invalid():
    rule = ModelCrossModelQueryRule(RuleConfig(thresholds={"max_findings_per_file": 3, "min_confidence": 0.74}))

    valid = Facts(project_path=".")
    valid.models.append(_model("app/Models/User.php", "User"))
    valid.methods.append(
        MethodInfo(
            name="active",
            class_name="User",
            class_fqcn="App\\Models\\User",
            file_path="app/Models/User.php",
            file_hash="user",
            line_start=20,
            line_end=32,
        )
    )
    valid.queries.append(
        QueryUsage(
            file_path="app/Models/User.php",
            line_number=24,
            method_name="active",
            model="User",
            method_chain="query->where->get",
            query_type="select",
        )
    )
    assert rule.analyze(valid) == []

    near_miss = Facts(project_path=".")
    near_miss.models.extend([_model("app/Models/User.php", "User"), _model("app/Models/AdminGrant.php", "AdminGrant")])
    near_miss.methods.append(
        MethodInfo(
            name="adminGrant",
            class_name="User",
            class_fqcn="App\\Models\\User",
            file_path="app/Models/User.php",
            file_hash="user",
            line_start=14,
            line_end=18,
            call_sites=["$this->belongsTo(AdminGrant::class)"],
        )
    )
    near_miss.queries.append(
        QueryUsage(
            file_path="app/Models/User.php",
            line_number=16,
            method_name="adminGrant",
            model="AdminGrant",
            method_chain="belongsTo",
            query_type="select",
        )
    )
    assert rule.analyze(near_miss) == []

    invalid = Facts(project_path=".")
    invalid.models.extend([_model("app/Models/User.php", "User"), _model("app/Models/AdminGrant.php", "AdminGrant")])
    invalid.methods.append(
        MethodInfo(
            name="isAdmin",
            class_name="User",
            class_fqcn="App\\Models\\User",
            file_path="app/Models/User.php",
            file_hash="user",
            line_start=40,
            line_end=56,
            call_sites=["AdminGrant::query()->active()->where('email', $this->email)->exists()"],
        )
    )
    invalid.queries.append(
        QueryUsage(
            file_path="app/Models/User.php",
            line_number=45,
            method_name="isAdmin",
            model="AdminGrant",
            method_chain="query->active->where->exists",
            query_type="select",
        )
    )
    findings = rule.analyze(invalid)
    assert len(findings) == 1
    assert findings[0].rule_id == "model-cross-model-query"


def test_action_class_naming_consistency_valid_near_invalid():
    rule = ActionClassNamingConsistencyRule(RuleConfig(thresholds={"max_findings_per_file": 20}))

    valid = Facts(project_path=".")
    valid.classes.extend(
        [
            ClassInfo(
                name="CreateUserAction",
                fqcn="App\\Actions\\Auth\\CreateUserAction",
                file_path="app/Actions/Auth/CreateUserAction.php",
                file_hash="a1",
                line_start=1,
                line_end=20,
            ),
            ClassInfo(
                name="DeleteUserAction",
                fqcn="App\\Actions\\Auth\\DeleteUserAction",
                file_path="app/Actions/Auth/DeleteUserAction.php",
                file_hash="a2",
                line_start=1,
                line_end=20,
            ),
        ]
    )
    assert rule.analyze(valid) == []

    near_miss = Facts(project_path=".")
    near_miss.classes.append(
        ClassInfo(
            name="AuthenticateGoogleUser",
            fqcn="App\\Actions\\Auth\\AuthenticateGoogleUser",
            file_path="app/Actions/Auth/AuthenticateGoogleUser.php",
            file_hash="a3",
            line_start=1,
            line_end=20,
        )
    )
    assert rule.analyze(near_miss) == []

    invalid = Facts(project_path=".")
    invalid.classes.extend(
        [
            ClassInfo(
                name="AuthenticateGoogleUser",
                fqcn="App\\Actions\\Auth\\AuthenticateGoogleUser",
                file_path="app/Actions/Auth/AuthenticateGoogleUser.php",
                file_hash="a4",
                line_start=1,
                line_end=20,
            ),
            ClassInfo(
                name="DeleteProfileAccount",
                fqcn="App\\Actions\\Profile\\DeleteProfileAccount",
                file_path="app/Actions/Profile/DeleteProfileAccount.php",
                file_hash="a5",
                line_start=1,
                line_end=20,
            ),
            ClassInfo(
                name="GrantAdminFromConsoleAction",
                fqcn="App\\Actions\\Admin\\GrantAdminFromConsoleAction",
                file_path="app/Actions/Admin/GrantAdminFromConsoleAction.php",
                file_hash="a6",
                line_start=1,
                line_end=20,
            ),
        ]
    )
    findings = rule.analyze(invalid)
    assert len(findings) == 2
    assert all(f.rule_id == "action-class-naming-consistency" for f in findings)


def test_g1_matrix_entries_are_active():
    matrix = ContextProfileMatrix.load_default()
    default_ctx = matrix.resolve_context()
    layered_ctx = matrix.resolve_context(
        explicit_profile="layered",
        explicit_project_type="portal_based_business_app",
        explicit_expectations={"services_actions_expected": True, "thin_controllers": True},
    )
    saas_ctx = matrix.resolve_context(
        explicit_profile="layered",
        explicit_project_type="saas_platform",
        explicit_capabilities={"saas": True, "multi_role_portal": True},
    )

    for rule_id in G1_RULES:
        calibrated = matrix.calibrate_rule(rule_id, default_ctx)
        assert isinstance(calibrated.get("thresholds"), dict)
        assert calibrated.get("severity") is not None

    assert matrix.calibrate_rule("controller-index-filter-duplication", layered_ctx)["severity"] == "medium"
    assert matrix.calibrate_rule("model-cross-model-query", saas_ctx)["severity"] == "medium"
    assert matrix.calibrate_rule("action-class-naming-consistency", layered_ctx)["severity"] == "medium"


def test_g1_rules_are_registered_and_enabled_in_profiles():
    assert set(G1_RULES).issubset(set(ALL_RULES.keys()))

    backend_root = Path(__file__).resolve().parents[1]
    startup = Ruleset.load(backend_root / "rulesets" / "startup.yaml")
    balanced = Ruleset.load(backend_root / "rulesets" / "balanced.yaml")
    strict = Ruleset.load(backend_root / "rulesets" / "strict.yaml")

    for rule_id in G1_RULES:
        assert startup.get_rule_config(rule_id).enabled is True
        assert balanced.get_rule_config(rule_id).enabled is True
        assert strict.get_rule_config(rule_id).enabled is True


def test_g1_rules_detect_rankingduel_like_fixture(fixture_path: Path):
    root = fixture_path / "laravel-gap-g1-mini"
    info = ProjectDetector(str(root)).detect()
    facts = FactsBuilder(info).build()
    metrics = MetricsAnalyzer().analyze(facts)

    engine = create_engine(ruleset=_ruleset_for(G1_RULES), selected_rules=G1_RULES)
    result = engine.run(facts, metrics=metrics, project_type=info.project_type.value)

    counts: dict[str, int] = {rule_id: 0 for rule_id in G1_RULES}
    for finding in result.findings:
        if finding.rule_id in counts:
            counts[finding.rule_id] += 1

    assert counts["controller-index-filter-duplication"] >= 2
    assert counts["model-cross-model-query"] >= 1
    assert counts["action-class-naming-consistency"] >= 1
