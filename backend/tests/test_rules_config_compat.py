from core.ruleset import RuleConfig
from rules.php.long_method import LongMethodRule
from rules.react.large_component import LargeComponentRule
from rules.php.dry_violation import DryViolationRule
from rules.laravel.missing_form_request import MissingFormRequestRule
from rules.laravel.service_extraction import ServiceExtractionRule
from rules.laravel.contract_suggestion import ContractSuggestionRule
from rules.php.god_class import GodClassRule
from rules.laravel.eager_loading import EagerLoadingRule
from rules.laravel.env_usage import EnvOutsideConfigRule
from rules.laravel.ioc_instead_of_new import IocInsteadOfNewRule

from schemas.facts import (
    Facts,
    ClassInfo,
    MethodInfo,
    ReactComponentInfo,
    DuplicateBlock,
    ValidationUsage,
    QueryUsage,
    EnvUsage,
)
from schemas.metrics import MethodMetrics


def test_long_method_accepts_max_loc_alias():
    facts = Facts(project_path=".")
    facts.methods.append(
        MethodInfo(
            name="foo",
            class_name="A",
            file_path="A.php",
            file_hash="deadbeef",
            line_start=1,
            line_end=100,
            loc=40,
        )
    )

    rule = LongMethodRule(RuleConfig(thresholds={"max_loc": 30}))
    res = rule.run(facts, project_type="")
    assert not res.skipped
    assert any(f.rule_id == "long-method" for f in res.findings)


def test_large_component_accepts_max_loc_alias():
    facts = Facts(project_path=".")
    facts.react_components.append(
        ReactComponentInfo(
            name="Big",
            file_path="Big.tsx",
            file_hash="deadbeef",
            line_start=1,
            line_end=400,
            loc=210,
        )
    )

    rule = LargeComponentRule(RuleConfig(thresholds={"max_loc": 200}))
    res = rule.run(facts, project_type="laravel_inertia_react")
    assert any(f.rule_id == "large-react-component" for f in res.findings)


def test_long_method_skips_mildly_over_threshold_simple_method_when_metrics_are_low():
    facts = Facts(project_path=".")
    method = MethodInfo(
        name="index",
        class_name="ReportController",
        class_fqcn="App\\Http\\Controllers\\ReportController",
        file_path="app/Http/Controllers/ReportController.php",
        file_hash="deadbeef",
        line_start=1,
        line_end=66,
        loc=66,
    )
    facts.methods.append(method)

    rule = LongMethodRule(RuleConfig(thresholds={"max_loc": 60}))
    res = rule.run(
        facts,
        project_type="laravel_api",
        metrics={
            method.method_fqn: MethodMetrics(
                method_fqn=method.method_fqn,
                file_path=method.file_path,
                cyclomatic_complexity=3,
                cognitive_complexity=4,
                conditional_count=1,
                query_count=1,
                validation_count=0,
                loop_count=0,
                has_business_logic=False,
            )
        },
    )
    assert res.findings == []


def test_dry_violation_accepts_min_token_count_alias():
    facts = Facts(project_path=".")
    facts.duplicates.append(
        DuplicateBlock(
            hash="h",
            token_count=60,
            occurrences=[("a.php", 1, 10), ("b.php", 5, 14)],
            code_snippet="x" * 100,
        )
    )

    rule = DryViolationRule(RuleConfig(thresholds={"min_token_count": 50, "min_occurrences": 2}))
    res = rule.run(facts, project_type="")
    assert any(f.rule_id == "dry-violation" for f in res.findings)


def test_dry_violation_skips_low_signal_transaction_wrapper_duplication_in_actions():
    facts = Facts(project_path=".")
    facts.duplicates.append(
        DuplicateBlock(
            hash="tx",
            token_count=72,
            occurrences=[
                ("app/Actions/Game/ExtendTimerAction.php", 20, 35),
                ("app/Actions/Game/ShortenTimerAction.php", 18, 33),
            ],
            code_snippet="return DB::transaction(function () use ($dto) { $session = $this->sessionRepo->findById($dto->sessionId); });",
        )
    )

    rule = DryViolationRule(RuleConfig(thresholds={"min_token_count": 50, "min_occurrences": 2}))
    res = rule.run(facts, project_type="")
    assert res.findings == []


def test_missing_form_request_accepts_max_validator_rules_alias():
    facts = Facts(project_path=".")
    facts.controllers.append(
        ClassInfo(
            name="UserController",
            fqcn="App\\Http\\Controllers\\UserController",
            file_path="UserController.php",
            file_hash="deadbeef",
            line_start=1,
            line_end=200,
        )
    )
    facts.validations.append(
        ValidationUsage(
            file_path="UserController.php",
            line_number=50,
            method_name="store",
            rules={"name": ["required"], "email": ["required"]},
            validation_type="inline",
        )
    )

    rule = MissingFormRequestRule(RuleConfig(thresholds={"max_validator_rules": 2}))
    res = rule.run(facts, project_type="laravel_api")
    assert any(f.rule_id == "missing-form-request" for f in res.findings)


def test_service_extraction_does_not_require_confidence():
    facts = Facts(project_path=".")
    facts.controllers.append(
        ClassInfo(
            name="OrderController",
            fqcn="App\\Http\\Controllers\\OrderController",
            file_path="OrderController.php",
            file_hash="deadbeef",
            line_start=1,
            line_end=300,
        )
    )
    facts.methods.append(
        MethodInfo(
            name="process",
            class_name="OrderController",
            file_path="OrderController.php",
            file_hash="deadbeef",
            line_start=10,
            line_end=80,
            loc=40,
            call_sites=["calculateTotal", "transformInput"],
        )
    )

    metrics = {
        "OrderController::process": MethodMetrics(
            method_fqn="OrderController::process",
            file_path="OrderController.php",
            cyclomatic_complexity=8,
            has_business_logic=True,
            business_logic_confidence=0.0,  # treated as unknown
        )
    }

    rule = ServiceExtractionRule(RuleConfig(thresholds={"min_business_loc": 15}))
    res = rule.run(facts, project_type="laravel_api", metrics=metrics)
    assert any(f.rule_id == "service-extraction" for f in res.findings)


def test_service_extraction_skips_controller_method_that_delegates_to_action():
    facts = Facts(project_path=".")
    facts.controllers.append(
        ClassInfo(
            name="GameController",
            fqcn="App\\Http\\Controllers\\GameController",
            file_path="app/Http/Controllers/GameController.php",
            file_hash="deadbeef",
            line_start=1,
            line_end=160,
        )
    )
    facts.methods.append(
        MethodInfo(
            name="castVote",
            class_name="GameController",
            class_fqcn="App\\Http\\Controllers\\GameController",
            file_path="app/Http/Controllers/GameController.php",
            file_hash="deadbeef",
            line_start=40,
            line_end=60,
            loc=21,
            parameters=["CastVoteRequest $request", "CastVoteAction $action"],
            call_sites=["$dto = new CastVoteDTO(...)", "$action->execute($dto)"],
        )
    )

    res = ServiceExtractionRule(RuleConfig(thresholds={"min_business_loc": 15})).run(
        facts, project_type="laravel_api"
    )
    assert res.findings == []


def test_contract_suggestion_parses_fqcn_params():
    facts = Facts(project_path=".")
    facts.methods.append(
        MethodInfo(
            name="__construct",
            class_name="UserController",
            file_path="UserController.php",
            file_hash="deadbeef",
            line_start=1,
            line_end=20,
            loc=10,
            parameters=["App\\Services\\UserService $svc"],
        )
    )

    rule = ContractSuggestionRule(RuleConfig())
    res = rule.run(facts, project_type="laravel_api")
    assert any(f.rule_id == "contract-suggestion" for f in res.findings)


def test_contract_suggestion_skips_concrete_type_when_class_already_implements_contract():
    facts = Facts(project_path=".")
    facts.classes.extend(
        [
            ClassInfo(
                name="UserService",
                fqcn="App\\Services\\UserService",
                file_path="app/Services/UserService.php",
                file_hash="svc",
                implements=["App\\Contracts\\UserServiceInterface"],
                line_start=1,
                line_end=40,
            ),
            ClassInfo(
                name="UserServiceInterface",
                fqcn="App\\Contracts\\UserServiceInterface",
                file_path="app/Contracts/UserServiceInterface.php",
                file_hash="iface",
                line_start=1,
                line_end=10,
            ),
        ]
    )
    facts.methods.append(
        MethodInfo(
            name="__construct",
            class_name="UserController",
            file_path="UserController.php",
            file_hash="deadbeef",
            line_start=1,
            line_end=20,
            loc=10,
            parameters=["App\\Services\\UserService $svc"],
        )
    )

    rule = ContractSuggestionRule(RuleConfig())
    res = rule.run(facts, project_type="laravel_api")
    assert res.findings == []


def test_god_class_triggers_on_size_and_methods():
    facts = Facts(project_path=".")
    facts.classes.append(
        ClassInfo(
            name="BigClass",
            fqcn="App\\BigClass",
            file_path="BigClass.php",
            file_hash="deadbeef",
            line_start=1,
            line_end=400,
        )
    )
    # 25 public methods
    for i in range(25):
        facts.methods.append(
            MethodInfo(
                name=f"m{i}",
                class_name="BigClass",
                file_path="BigClass.php",
                file_hash="deadbeef",
                line_start=10 + i * 5,
                line_end=10 + i * 5 + 3,
                loc=4,
                visibility="public",
            )
        )

    rule = GodClassRule(RuleConfig(thresholds={"max_loc": 300, "max_methods": 20}))
    res = rule.run(facts, project_type="")
    assert any(f.rule_id == "god-class" for f in res.findings)


def test_eager_loading_triggers_on_loop_query_without_eager_loading():
    facts = Facts(project_path=".")
    facts.queries.append(
        QueryUsage(
            file_path="app/Http/Controllers/UserController.php",
            line_number=10,
            method_name="index",
            model="User",
            method_chain="where->get",
            has_eager_loading=False,
            n_plus_one_risk="high",
            n_plus_one_reason="Query detected inside a loop context; consider eager loading.",
        )
    )

    rule = EagerLoadingRule(RuleConfig())
    res = rule.run(facts, project_type="laravel_api")
    assert any(f.rule_id == "eager-loading" for f in res.findings)


def test_env_outside_config_creates_finding():
    facts = Facts(project_path=".")
    facts.env_usages.append(EnvUsage(file_path="app/Services/Foo.php", line_number=12, snippet="return env('X');"))

    rule = EnvOutsideConfigRule(RuleConfig())
    res = rule.run(facts, project_type="laravel_api")
    assert any(f.rule_id == "env-outside-config" for f in res.findings)


def test_ioc_instead_of_new_flags_controller_instantiation():
    facts = Facts(project_path=".")
    facts.controllers.append(
        ClassInfo(
            name="UserController",
            fqcn="App\\Http\\Controllers\\UserController",
            file_path="app/Http/Controllers/UserController.php",
            file_hash="deadbeef",
            line_start=1,
            line_end=200,
        )
    )
    facts.methods.append(
        MethodInfo(
            name="store",
            class_name="UserController",
            file_path="app/Http/Controllers/UserController.php",
            file_hash="deadbeef",
            line_start=10,
            line_end=40,
            loc=31,
            instantiations=["App\\Services\\UserService"],
        )
    )

    rule = IocInsteadOfNewRule(RuleConfig(thresholds={"max_instantiations": 0}))
    res = rule.run(facts, project_type="laravel_api")
    assert any(f.rule_id == "ioc-instead-of-new" for f in res.findings)
