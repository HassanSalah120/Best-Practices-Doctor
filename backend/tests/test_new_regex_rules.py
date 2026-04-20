import re

from core.ruleset import RuleConfig
from schemas.facts import Facts, ClassInfo, RouteInfo

from rules.laravel.no_json_encode_in_controllers import NoJsonEncodeInControllersRule
from rules.laravel.no_log_debug_in_app import NoLogDebugInAppRule
from rules.laravel.no_closure_routes import NoClosureRoutesRule
from rules.laravel.heavy_logic_in_routes import HeavyLogicInRoutesRule
from rules.laravel.api_resource_usage import ApiResourceUsageRule
from rules.laravel.missing_throttle_on_auth_api_routes import MissingThrottleOnAuthApiRoutesRule
from rules.laravel.missing_auth_on_mutating_api_routes import MissingAuthOnMutatingApiRoutesRule


def _facts_with_controller_file(fp: str) -> Facts:
    f = Facts(project_path="x")
    f.files = [fp]
    f.controllers = [ClassInfo(name="XController", fqcn="App\\Http\\Controllers\\XController", file_path=fp, file_hash="h")]
    return f


def test_no_json_encode_in_controllers_positive_and_negative():
    # Disable API context requirement for test - just check pattern matching
    rule = NoJsonEncodeInControllersRule(RuleConfig(thresholds={"require_api_context": False}))

    facts = _facts_with_controller_file("app/Http/Controllers/XController.php")
    pos = "class X { public function a(){ return json_encode($x); } }"
    neg = "class X { public function a(){ return response()->json($x); } }"

    assert rule.analyze_regex(facts.files[0], pos, facts)
    assert not rule.analyze_regex(facts.files[0], neg, facts)


def test_no_log_debug_in_app_positive_and_negative():
    rule = NoLogDebugInAppRule(RuleConfig())
    facts = Facts(project_path="x")

    assert rule.analyze_regex("app/Services/S.php", "Log::debug('x');", facts)
    assert not rule.analyze_regex("routes/web.php", "Log::debug('x');", facts)


def test_no_closure_routes_positive_and_negative():
    rule = NoClosureRoutesRule(RuleConfig())
    facts = Facts(project_path="x")

    pos = "Route::get('/x', function () { return 'ok'; });"
    neg = "Route::get('/x', [XController::class, 'index']);"

    assert rule.analyze_regex("routes/web.php", pos, facts)
    assert not rule.analyze_regex("routes/web.php", neg, facts)


def test_heavy_logic_in_routes_positive_and_negative():
    rule = HeavyLogicInRoutesRule(RuleConfig())
    facts = Facts(project_path="x")

    pos = "Route::get('/x', function () { DB::select('select 1'); });"
    neg = "Route::get('/x', [XController::class, 'index']);"

    assert rule.analyze_regex("routes/api.php", pos, facts)
    assert not rule.analyze_regex("routes/api.php", neg, facts)


def test_api_resource_usage_positive_and_negative():
    rule = ApiResourceUsageRule(RuleConfig())
    facts = Facts(project_path="x")

    pos = "class C { public function index(){ return ['a' => 1]; } }"
    neg = "use Illuminate\\Http\\Resources\\Json\\JsonResource; class C { public function index(){ return new UserResource($u); } }"

    assert rule.analyze_regex("app/Http/Controllers/Api/UserController.php", pos, facts)
    assert not rule.analyze_regex("app/Http/Controllers/Api/UserController.php", neg, facts)


def test_missing_throttle_on_auth_api_routes_positive_and_negative():
    rule = MissingThrottleOnAuthApiRoutesRule(RuleConfig())
    facts = Facts(project_path="x")

    pos = "Route::post('/login', [AuthController::class, 'login']);"
    neg = "Route::post('/login', [AuthController::class, 'login'])->middleware('throttle:api');"

    assert rule.analyze_regex("routes/api.php", pos, facts)
    assert not rule.analyze_regex("routes/api.php", neg, facts)


def test_missing_auth_on_mutating_api_routes_positive_and_negative():
    rule = MissingAuthOnMutatingApiRoutesRule(RuleConfig())
    facts = Facts(project_path="x")
    facts.routes = [
        RouteInfo(
            method="POST",
            uri="/patients",
            controller="PatientController",
            action="store",
            middleware=[],
            file_path="routes/api.php",
            line_number=3,
        ),
        RouteInfo(
            method="POST",
            uri="/patients-auth",
            controller="PatientController",
            action="store",
            middleware=["auth:sanctum"],
            file_path="routes/api.php",
            line_number=5,
        ),
        RouteInfo(
            method="POST",
            uri="/login",
            controller="AuthController",
            action="login",
            middleware=[],
            file_path="routes/api.php",
            line_number=8,
        ),
    ]

    findings = rule.analyze_regex("routes/api.php", "", facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "missing-auth-on-mutating-api-routes"
    assert findings[0].line_start == 3
