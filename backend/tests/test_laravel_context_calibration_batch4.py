from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from analysis.facts_builder import FactsBuilder
from analysis.metrics_analyzer import MetricsAnalyzer
from core.context_profiles import ContextProfileMatrix
from core.detector import ProjectDetector
from core.rule_engine import ALL_RULES, create_engine
from core.ruleset import RuleConfig, Ruleset
from rules.laravel.inertia_shared_props_eager_query import InertiaSharedPropsEagerQueryRule
from rules.laravel.inertia_shared_props_sensitive_data import InertiaSharedPropsSensitiveDataRule
from rules.laravel.missing_cache_for_reference_data import MissingCacheForReferenceDataRule
from rules.laravel.missing_pagination import MissingPaginationRule
from rules.laravel.n_plus_one_risk import NPlusOneRiskRule
from rules.laravel.no_json_encode_in_controllers import NoJsonEncodeInControllersRule
from rules.laravel.registration_missing_registered_event import RegistrationMissingRegisteredEventRule
from rules.laravel.user_model_missing_must_verify_email import UserModelMissingMustVerifyEmailRule
from schemas.facts import ClassInfo, Facts, MethodInfo, QueryUsage, RelationAccess, RouteInfo


BATCH4_RULES = [
    "missing-pagination",
    "no-json-encode-in-controllers",
    "registration-missing-registered-event",
    "user-model-missing-must-verify-email",
    "inertia-shared-props-sensitive-data",
    "inertia-shared-props-eager-query",
    "missing-cache-for-reference-data",
    "n-plus-one-risk",
]


def _controller(path: str, name: str) -> ClassInfo:
    return ClassInfo(
        name=name,
        fqcn=f"App\\Http\\Controllers\\{name}",
        file_path=path,
        file_hash="fixture",
        line_start=1,
        line_end=120,
    )


def _ruleset_for(rule_ids: list[str]) -> Ruleset:
    rules = {rid: RuleConfig(enabled=False) for rid in ALL_RULES.keys()}
    for rule_id in rule_ids:
        rules[rule_id] = RuleConfig(enabled=True)
    return Ruleset(rules=rules, name="strict")


def test_missing_pagination_batch4_valid_near_invalid():
    rule = MissingPaginationRule(
        RuleConfig(
            thresholds={
                "require_api_context": True,
                "min_api_context_signals": 1,
                "min_multi_record_signals": 2,
                "large_model_only": True,
                "suppress_export_flows": True,
                "min_confidence": 0.7,
            }
        )
    )

    valid = Facts(project_path=".")
    valid.routes.append(
        RouteInfo(
            method="GET",
            uri="api/users",
            action="UserController@index",
            file_path="routes/api.php",
            line_number=7,
        )
    )
    valid.queries.append(
        QueryUsage(
            file_path="app/Http/Controllers/Api/UserController.php",
            line_number=22,
            method_name="index",
            model="User",
            method_chain="query->paginate(15)",
            query_type="select",
        )
    )
    assert rule.analyze(valid) == []

    near_miss = Facts(project_path=".")
    near_miss.routes.append(
        RouteInfo(
            method="GET",
            uri="api/users/export",
            action="UserController@exportCsv",
            file_path="routes/api.php",
            line_number=12,
        )
    )
    near_miss.queries.append(
        QueryUsage(
            file_path="app/Http/Controllers/Api/UserController.php",
            line_number=33,
            method_name="exportCsv",
            model="User",
            method_chain="query->get()",
            query_type="select",
        )
    )
    assert rule.analyze(near_miss) == []

    invalid = Facts(project_path=".")
    invalid.routes.append(
        RouteInfo(
            method="GET",
            uri="api/patients",
            action="PatientController@index",
            file_path="routes/api.php",
            line_number=18,
        )
    )
    invalid.queries.append(
        QueryUsage(
            file_path="app/Http/Controllers/Api/PatientController.php",
            line_number=40,
            method_name="index",
            model="Patient",
            method_chain="query->get()",
            query_type="select",
        )
    )
    assert len(rule.analyze(invalid)) == 1


def test_no_json_encode_in_controllers_batch4_valid_near_invalid():
    rule = NoJsonEncodeInControllersRule(
        RuleConfig(
            thresholds={
                "require_api_context": True,
                "require_return_context": True,
                "min_confidence": 0.7,
            }
        )
    )

    facts = Facts(project_path=".")
    controller_path = "app/Http/Controllers/Api/TokenController.php"
    facts.controllers.append(_controller(controller_path, "TokenController"))
    facts.routes.append(
        RouteInfo(
            method="POST",
            uri="api/token/issue",
            action="TokenController@issue",
            file_path="routes/api.php",
            line_number=9,
        )
    )

    valid = """
<?php
namespace App\\Http\\Controllers\\Api;
class TokenController {
    public function issue() {
        return response()->json(['status' => 'ok']);
    }
}
"""
    near_miss = """
<?php
namespace App\\Http\\Controllers\\Api;
class TokenController {
    public function issue() {
        $payload = json_encode(['status' => 'ok']);
        return response()->json(['payload' => $payload]);
    }
}
"""
    invalid = """
<?php
namespace App\\Http\\Controllers\\Api;
class TokenController {
    public function issue() {
        return json_encode(['status' => 'ok']);
    }
}
"""

    assert rule.analyze_regex(controller_path, valid, facts) == []
    assert rule.analyze_regex(controller_path, near_miss, facts) == []
    assert len(rule.analyze_regex(controller_path, invalid, facts)) == 1


def test_registration_missing_registered_event_batch4_valid_near_invalid():
    rule = RegistrationMissingRegisteredEventRule(
        RuleConfig(
            thresholds={
                "min_confidence": 0.7,
                "min_self_service_signals": 1,
                "require_self_service_context": True,
                "suppress_admin_only_flows": True,
            }
        )
    )

    valid_facts = Facts(project_path=".")
    valid_facts.routes.append(
        RouteInfo(
            method="POST",
            uri="/register",
            controller="Auth\\RegisteredUserController",
            action="RegisteredUserController@store",
            middleware=["guest"],
            file_path="routes/web.php",
            line_number=14,
        )
    )
    valid = """
<?php
namespace App\\Http\\Controllers\\Auth;
class RegisteredUserController {
    public function store() {
        $user = User::create(['email' => $request->email]);
        event(new Registered($user));
    }
}
"""
    assert (
        rule.analyze_regex("app/Http/Controllers/Auth/RegisteredUserController.php", valid, valid_facts) == []
    )

    near_miss_facts = Facts(project_path=".")
    near_miss_facts.routes.append(
        RouteInfo(
            method="POST",
            uri="/admin/users",
            controller="Admin\\AdminUsersController",
            action="AdminUsersController@store",
            middleware=["auth", "admin"],
            file_path="routes/web.php",
            line_number=20,
        )
    )
    near_miss = """
<?php
namespace App\\Http\\Controllers\\Admin;
class AdminUsersController {
    public function store() {
        $user = User::create(['email' => $request->email]);
        return back();
    }
}
"""
    assert rule.analyze_regex("app/Http/Controllers/Admin/AdminUsersController.php", near_miss, near_miss_facts) == []

    invalid_facts = Facts(project_path=".")
    invalid_facts.routes.append(
        RouteInfo(
            method="POST",
            uri="/register",
            controller="Auth\\RegisteredUserController",
            action="RegisteredUserController@store",
            middleware=["guest"],
            file_path="routes/web.php",
            line_number=14,
        )
    )
    invalid = """
<?php
namespace App\\Http\\Controllers\\Auth;
class RegisteredUserController {
    public function store() {
        $user = User::create(['email' => $request->email]);
        return redirect('/dashboard');
    }
}
"""
    assert len(rule.analyze_regex("app/Http/Controllers/Auth/RegisteredUserController.php", invalid, invalid_facts)) == 1


def test_user_model_missing_must_verify_email_batch4_valid_near_invalid():
    rule = UserModelMissingMustVerifyEmailRule(
        RuleConfig(
            thresholds={
                "min_confidence": 0.78,
                "skip_for_token_api_only": True,
            }
        )
    )
    file_path = "app/Models/User.php"

    valid = """
<?php
namespace App\\Models;
use Illuminate\\Contracts\\Auth\\MustVerifyEmail;
use Illuminate\\Foundation\\Auth\\User as Authenticatable;
class User extends Authenticatable implements MustVerifyEmail {}
"""
    assert rule.analyze_regex(file_path, valid, Facts(project_path=".")) == []

    near_miss_facts = Facts(project_path=".")
    near_miss_facts.project_context.backend_architecture_profile = "api-first"
    near_miss_facts.project_context.project_business_context = "api_backend"
    near_miss_facts.routes.append(
        RouteInfo(
            method="POST",
            uri="api/token/login",
            action="AuthController@login",
            middleware=["throttle:api", "auth:sanctum"],
            file_path="routes/api.php",
            line_number=10,
        )
    )
    near_miss = """
<?php
namespace App\\Models;
use Illuminate\\Foundation\\Auth\\User as Authenticatable;
class User extends Authenticatable {}
"""
    assert rule.analyze_regex(file_path, near_miss, near_miss_facts) == []

    invalid_facts = Facts(project_path=".")
    invalid_facts.routes.append(
        RouteInfo(
            method="GET",
            uri="/billing/portal",
            action="BillingController@show",
            middleware=["web", "auth", "verified"],
            file_path="routes/web.php",
            line_number=18,
        )
    )
    invalid = """
<?php
namespace App\\Models;
use Illuminate\\Foundation\\Auth\\User as Authenticatable;
class User extends Authenticatable {}
"""
    assert len(rule.analyze_regex(file_path, invalid, invalid_facts)) == 1


def test_inertia_shared_props_sensitive_data_batch4_valid_near_invalid():
    rule = InertiaSharedPropsSensitiveDataRule(
        RuleConfig(
            thresholds={
                "min_confidence": 0.78,
                "min_signal_count": 2,
                "require_inertia_context": True,
                "require_global_share_context": True,
            }
        )
    )
    facts = Facts(project_path=".")
    file_path = "app/Http/Middleware/HandleInertiaRequests.php"

    valid = """
<?php
class HandleInertiaRequests {
    public function share(Request $request): array {
        return array_merge(parent::share($request), [
            'auth.user' => fn () => $request->user()?->only('id', 'name', 'email'),
        ]);
    }
}
"""
    near_miss = """
<?php
class UserBadge {
    public function props(Request $request): array {
        return ['auth.user' => $request->user()];
    }
}
"""
    invalid = """
<?php
class HandleInertiaRequests {
    public function share(Request $request): array {
        return array_merge(parent::share($request), [
            'auth.user' => $request->user(),
        ]);
    }
}
"""

    assert rule.analyze_regex(file_path, valid, facts) == []
    assert rule.analyze_regex("app/Services/UserBadge.php", near_miss, facts) == []
    assert len(rule.analyze_regex(file_path, invalid, facts)) == 1


def test_inertia_shared_props_eager_query_batch4_valid_near_invalid():
    rule = InertiaSharedPropsEagerQueryRule(
        RuleConfig(
            thresholds={
                "min_confidence": 0.74,
                "min_signal_count": 2,
                "require_inertia_context": True,
                "require_global_share_context": True,
                "allow_lazy_or_cached": True,
            }
        )
    )
    facts = Facts(project_path=".")
    file_path = "app/Http/Middleware/HandleInertiaRequests.php"

    valid = """
<?php
class HandleInertiaRequests {
    public function share(Request $request): array {
        return array_merge(parent::share($request), [
            'stats' => fn () => Order::count(),
        ]);
    }
}
"""
    near_miss = """
<?php
class HandleInertiaRequests {
    public function share(Request $request): array {
        return array_merge(parent::share($request), [
            'stats' => Cache::remember('orders.count', 300, fn () => Order::count()),
        ]);
    }
}
"""
    delegated_valid = """
<?php
class HandleInertiaRequests {
    public function share(Request $request): array {
        return array_merge(parent::share($request), [
            'stats' => fn () => $this->resolveMetrics(),
        ]);
    }

    private function resolveMetrics(): array {
        return ['orders' => Order::count()];
    }
}
"""
    delegated_invalid = """
<?php
class HandleInertiaRequests {
    public function share(Request $request): array {
        return array_merge(parent::share($request), [
            'stats' => $this->resolveMetrics(),
        ]);
    }

    private function resolveMetrics(): array {
        return ['orders' => Order::count()];
    }
}
"""
    invalid = """
<?php
class HandleInertiaRequests {
    public function share(Request $request): array {
        return array_merge(parent::share($request), [
            'stats' => Order::count(),
        ]);
    }
}
"""

    assert rule.analyze_regex(file_path, valid, facts) == []
    assert rule.analyze_regex(file_path, near_miss, facts) == []
    assert rule.analyze_regex(file_path, delegated_valid, facts) == []
    assert len(rule.analyze_regex(file_path, delegated_invalid, facts)) == 1
    assert len(rule.analyze_regex(file_path, invalid, facts)) == 1


def test_missing_cache_for_reference_data_batch4_valid_near_invalid():
    rule = MissingCacheForReferenceDataRule(
        RuleConfig(
            thresholds={
                "min_confidence": 0.8,
                "require_repeated_reference_access": True,
                "min_reference_query_count": 2,
                "require_project_cache_usage": True,
                "require_service_or_repository_context": True,
            }
        )
    )

    temp_root = Path("backend/tests/.tmp_batch4_cache") / str(uuid4())
    valid_root = temp_root / "valid"
    (valid_root / "app/Repositories").mkdir(parents=True, exist_ok=True)
    (valid_root / "app/Repositories/RoleRepository.php").write_text(
        """<?php
use Illuminate\\Support\\Facades\\Cache;
class RoleRepository {
    public function all() {
        return Cache::remember('roles.all', 3600, fn() => Role::all());
    }
}
""",
        encoding="utf-8",
    )
    valid = Facts(project_path=str(valid_root))
    valid.methods.append(
        MethodInfo(
            name="all",
            class_name="RoleRepository",
            class_fqcn="App\\Repositories\\RoleRepository",
            file_path="app/Repositories/RoleRepository.php",
            file_hash="v1",
            call_sites=["Cache::remember('roles.all', 3600, fn() => Role::all())"],
        )
    )
    valid.queries.append(
        QueryUsage(
            file_path="app/Repositories/RoleRepository.php",
            line_number=5,
            method_name="all",
            model="Role",
            method_chain="all()",
            query_type="select",
        )
    )
    assert rule.analyze(valid) == []

    near_root = temp_root / "near"
    (near_root / "app/Http/Controllers").mkdir(parents=True, exist_ok=True)
    (near_root / "app/Services").mkdir(parents=True, exist_ok=True)
    (near_root / "app/Http/Controllers/SettingsController.php").write_text(
        """<?php
class SettingsController {
    public function index() {
        return Setting::all();
    }
}
""",
        encoding="utf-8",
    )
    near = Facts(project_path=str(near_root))
    near.project_context.project_business_context = "internal_admin_system"
    near.methods.append(
        MethodInfo(
            name="cacheProbe",
            class_name="CacheProbe",
            class_fqcn="App\\Services\\CacheProbe",
            file_path="app/Services/CacheProbe.php",
            file_hash="n1",
            call_sites=["Cache::remember('probe', 60, fn() => ['ok' => true])"],
        )
    )
    near.queries.append(
        QueryUsage(
            file_path="app/Http/Controllers/SettingsController.php",
            line_number=4,
            method_name="index",
            model="Setting",
            method_chain="all()",
            query_type="select",
        )
    )
    assert rule.analyze(near) == []

    invalid_root = temp_root / "invalid"
    (invalid_root / "app/Services").mkdir(parents=True, exist_ok=True)
    (invalid_root / "app/Repositories").mkdir(parents=True, exist_ok=True)
    (invalid_root / "app/Services/CountryService.php").write_text(
        """<?php
class CountryService {
    public function all() {
        return Country::all();
    }
}
""",
        encoding="utf-8",
    )
    (invalid_root / "app/Repositories/CountryRepository.php").write_text(
        """<?php
class CountryRepository {
    public function list() {
        return Country::query()->get();
    }
}
""",
        encoding="utf-8",
    )
    invalid = Facts(project_path=str(invalid_root))
    invalid.project_context.project_business_context = "saas_platform"
    invalid.methods.append(
        MethodInfo(
            name="cacheProbe",
            class_name="CacheProbe",
            class_fqcn="App\\Services\\CacheProbe",
            file_path="app/Services/CacheProbe.php",
            file_hash="i1",
            call_sites=["Cache::remember('probe', 60, fn() => ['ok' => true])"],
        )
    )
    invalid.queries.extend(
        [
            QueryUsage(
                file_path="app/Services/CountryService.php",
                line_number=4,
                method_name="all",
                model="Country",
                method_chain="all()",
                query_type="select",
            ),
                QueryUsage(
                    file_path="app/Repositories/CountryRepository.php",
                    line_number=4,
                    method_name="list",
                    model="Country",
                    method_chain="query->get()",
                    query_type="select",
                ),
            ]
        )
    assert len(rule.analyze(invalid)) >= 1


def test_n_plus_one_risk_batch4_valid_near_invalid():
    rule = NPlusOneRiskRule(
        RuleConfig(
            thresholds={
                "min_confidence": 0.72,
                "require_model_match": False,
                "require_local_query_context_or_strong_relation_signal": True,
                "require_select_query_context": True,
                "min_evidence_signals": 2,
            }
        )
    )

    def _relation_model(facts: Facts) -> None:
        facts.classes.append(
            ClassInfo(
                name="Patient",
                fqcn="App\\Models\\Patient",
                file_path="app/Models/Patient.php",
                file_hash="m1",
                line_start=1,
                line_end=80,
            )
        )
        facts.methods.append(
            MethodInfo(
                name="clinic",
                class_name="Patient",
                class_fqcn="App\\Models\\Patient",
                file_path="app/Models/Patient.php",
                file_hash="m1",
                line_start=20,
                line_end=28,
                call_sites=["$this->belongsTo(Clinic::class)"],
            )
        )

    valid = Facts(project_path=".")
    _relation_model(valid)
    valid.methods.append(
        MethodInfo(
            name="index",
            class_name="PatientController",
            class_fqcn="App\\Http\\Controllers\\Api\\PatientController",
            file_path="app/Http/Controllers/Api/PatientController.php",
            file_hash="c1",
            line_start=10,
            line_end=42,
            loc=33,
        )
    )
    valid.queries.append(
        QueryUsage(
            file_path="app/Http/Controllers/Api/PatientController.php",
            line_number=15,
            method_name="index",
            model="Patient",
            method_chain="query->with('clinic')->get",
            query_type="select",
            has_eager_loading=True,
        )
    )
    valid.relation_accesses.append(
        RelationAccess(
            file_path="app/Http/Controllers/Api/PatientController.php",
            line_number=24,
            method_name="index",
            class_fqcn="App\\Http\\Controllers\\Api\\PatientController",
            base_var="$patient",
            relation="clinic",
            loop_kind="foreach",
            access_type="property",
        )
    )
    assert rule.analyze(valid) == []

    near_miss = Facts(project_path=".")
    _relation_model(near_miss)
    near_miss.methods.append(
        MethodInfo(
            name="mapRows",
            class_name="PatientFormatter",
            class_fqcn="App\\Services\\PatientFormatter",
            file_path="app/Services/PatientFormatter.php",
            file_hash="s1",
            line_start=10,
            line_end=36,
            loc=27,
            parameters=["Collection $patients"],
        )
    )
    near_miss.relation_accesses.append(
        RelationAccess(
            file_path="app/Services/PatientFormatter.php",
            line_number=22,
            method_name="mapRows",
            class_fqcn="App\\Services\\PatientFormatter",
            base_var="$patient",
            relation="clinic",
            loop_kind="collection_map",
            access_type="property",
        )
    )
    assert rule.analyze(near_miss) == []

    invalid = Facts(project_path=".")
    _relation_model(invalid)
    invalid.methods.append(
        MethodInfo(
            name="index",
            class_name="PatientController",
            class_fqcn="App\\Http\\Controllers\\Api\\PatientController",
            file_path="app/Http/Controllers/Api/PatientController.php",
            file_hash="c2",
            line_start=10,
            line_end=44,
            loc=35,
        )
    )
    invalid.queries.append(
        QueryUsage(
            file_path="app/Http/Controllers/Api/PatientController.php",
            line_number=16,
            method_name="index",
            model="Patient",
            method_chain="query->get",
            query_type="select",
            has_eager_loading=False,
        )
    )
    invalid.relation_accesses.append(
        RelationAccess(
            file_path="app/Http/Controllers/Api/PatientController.php",
            line_number=26,
            method_name="index",
            class_fqcn="App\\Http\\Controllers\\Api\\PatientController",
            base_var="$patient",
            relation="clinic",
            loop_kind="foreach",
            access_type="property",
        )
    )
    assert len(rule.analyze(invalid)) == 1


def test_batch4_context_matrix_entries_are_active():
    matrix = ContextProfileMatrix.load_default()
    default_ctx = matrix.resolve_context()
    api_ctx = matrix.resolve_context(explicit_profile="api-first", explicit_project_type="api_backend")
    saas_ctx = matrix.resolve_context(
        explicit_profile="layered",
        explicit_project_type="saas_platform",
        explicit_capabilities={"billing": True},
    )
    admin_ctx = matrix.resolve_context(
        explicit_profile="mvc",
        explicit_project_type="internal_admin_system",
    )

    for rule_id in BATCH4_RULES:
        calibrated = matrix.calibrate_rule(rule_id, default_ctx)
        assert isinstance(calibrated.get("thresholds"), dict)
        assert calibrated.get("severity") is not None

    assert matrix.calibrate_rule("no-json-encode-in-controllers", api_ctx)["severity"] == "high"
    assert matrix.calibrate_rule("missing-cache-for-reference-data", saas_ctx)["severity"] in {"medium", "high"}
    assert matrix.calibrate_rule("n-plus-one-risk", admin_ctx)["severity"] == "low"


def test_batch4_rules_validate_across_context_fixtures(fixture_path: Path):
    fixtures = {
        "mvc": "laravel-mvc-invalid-mini",
        "layered": "laravel-layered-near-miss-mini",
        "api_first": "laravel-api-first-invalid-mini",
        "mixed_public_dashboard": "laravel-blade-mini",
        "portal_style": "imposter-inertia-architecture-mini",
    }

    engine = create_engine(ruleset=_ruleset_for(BATCH4_RULES), selected_rules=BATCH4_RULES)
    for _, fixture_name in fixtures.items():
        root = fixture_path / fixture_name
        info = ProjectDetector(str(root)).detect()
        facts = FactsBuilder(info).build()
        metrics = MetricsAnalyzer().analyze(facts)
        result = engine.run(facts, metrics=metrics, project_type=info.project_type.value)
        assert isinstance(result.findings, list)
        assert facts.project_context.backend_framework in {"laravel", "unknown"}
