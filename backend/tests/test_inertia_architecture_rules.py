from __future__ import annotations

import os
import tempfile

from core.ruleset import RuleConfig
from rules.laravel.inertia_api_route_returns_inertia import InertiaApiRouteReturnsInertiaRule
from rules.laravel.inertia_conditional_wants_json import InertiaConditionalWantsJsonRule
from rules.laravel.inertia_get_with_side_effects import InertiaGetWithSideEffectsRule
from rules.laravel.inertia_hybrid_controller import InertiaHybridControllerRule
from rules.laravel.inertia_post_returns_render import InertiaPostReturnsRenderRule
from rules.laravel.inertia_route_returns_json_response import InertiaRouteReturnsJsonResponseRule
from rules.laravel.inertia_session_flash_on_api import InertiaSessionFlashOnApiRule
from schemas.facts import Facts, MethodInfo, RouteInfo


def _facts(routes: list | None = None, methods: list | None = None, project_type: str = "laravel_inertia_react") -> Facts:
    facts = Facts(project_path=".")
    facts.project_context.project_type = project_type
    if routes:
        facts.routes = routes
    if methods:
        facts.methods = methods
    return facts


def _route(method: str, uri: str, controller: str, action: str, middleware: list | None = None, line: int = 10, file_path: str | None = None) -> RouteInfo:
    if file_path is None:
        file_path = "routes/api.php" if uri.startswith("api/") else "routes/web.php"
    return RouteInfo(
        method=method,
        uri=uri,
        controller=controller,
        action=action,
        middleware=middleware or [],
        file_path=file_path,
        line_number=line,
    )


# ==============================================================================
# Rule 2: inertia-conditional-wants-json
# ==============================================================================

def test_conditional_wants_json_valid():
    rule = InertiaConditionalWantsJsonRule(RuleConfig(thresholds={}))
    facts = _facts()
    valid = "<?php return Inertia::render('Users/Index', ['users' => $users]);"
    assert rule.analyze_regex("app/Http/Controllers/UserController.php", valid, facts) == []


def test_conditional_wants_json_near_miss_only_wants_json():
    rule = InertiaConditionalWantsJsonRule(RuleConfig(thresholds={}))
    facts = _facts()
    near_miss = "<?php if ($request->wantsJson()) { return response()->json($data); }"
    assert rule.analyze_regex("app/Http/Controllers/UserController.php", near_miss, facts) == []


def test_conditional_wants_json_invalid():
    rule = InertiaConditionalWantsJsonRule(RuleConfig(thresholds={}))
    facts = _facts()
    invalid = (
        "<?php\n"
        "public function index(Request $request)\n"
        "{\n"
        "    $users = User::all();\n"
        "    if ($request->wantsJson()) {\n"
        "        return response()->json($users);\n"
        "    }\n"
        "    return Inertia::render('Users/Index', ['users' => $users]);\n"
        "}"
    )
    findings = rule.analyze_regex("app/Http/Controllers/UserController.php", invalid, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "inertia-conditional-wants-json"


def test_conditional_wants_json_skips_api_method():
    rule = InertiaConditionalWantsJsonRule(RuleConfig(thresholds={}))
    facts = _facts()
    content = (
        "<?php\n"
        "public function apiIndex(Request $request)\n"
        "{\n"
        "    if ($request->wantsJson()) {\n"
        "        return response()->json($users);\n"
        "    }\n"
        "    return Inertia::render('Users/Index', ['users' => $users]);\n"
        "}"
    )
    assert rule.analyze_regex("app/Http/Controllers/UserController.php", content, facts) == []


def test_conditional_wants_json_skips_test_path():
    rule = InertiaConditionalWantsJsonRule(RuleConfig(thresholds={}))
    facts = _facts()
    invalid = (
        "<?php\n"
        "if ($request->wantsJson()) {\n"
        "    return response()->json($users);\n"
        "}\n"
        "return Inertia::render('Users/Index', ['users' => $users]);"
    )
    assert rule.analyze_regex("tests/Feature/UserControllerTest.php", invalid, facts) == []


def test_conditional_wants_json_expects_json():
    rule = InertiaConditionalWantsJsonRule(RuleConfig(thresholds={}))
    facts = _facts()
    invalid = (
        "<?php\n"
        "public function index(Request $request)\n"
        "{\n"
        "    if ($request->expectsJson()) {\n"
        "        return response()->json($users);\n"
        "    }\n"
        "    return Inertia::render('Users/Index', ['users' => $users]);\n"
        "}"
    )
    findings = rule.analyze_regex("app/Http/Controllers/UserController.php", invalid, facts)
    assert len(findings) == 1


# ==============================================================================
# Rule 1: inertia-route-returns-json-response
# ==============================================================================

def test_route_returns_json_response_valid_inertia():
    rule = InertiaRouteReturnsJsonResponseRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("GET", "users", "UserController", "index")])
    valid = "<?php return Inertia::render('Users/Index', ['users' => $users]);"
    assert rule.analyze_regex("app/Http/Controllers/UserController.php", valid, facts) == []


def test_route_returns_json_response_near_miss_no_json():
    rule = InertiaRouteReturnsJsonResponseRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("GET", "users", "UserController", "index")])
    near_miss = "<?php $users = User::all(); return view('users.index', compact('users'));"
    assert rule.analyze_regex("app/Http/Controllers/UserController.php", near_miss, facts) == []


def test_route_returns_json_response_invalid():
    rule = InertiaRouteReturnsJsonResponseRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("GET", "users", "UserController", "index")])
    invalid = "<?php $users = User::all(); return response()->json($users);"
    findings = rule.analyze_regex("app/Http/Controllers/UserController.php", invalid, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "inertia-route-returns-json-response"


def test_route_returns_json_response_skips_api_route():
    rule = InertiaRouteReturnsJsonResponseRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("GET", "api/users", "UserController", "index")])
    invalid = "<?php return response()->json($users);"
    assert rule.analyze_regex("app/Http/Controllers/UserController.php", invalid, facts) == []


def test_route_returns_json_response_skips_wants_json():
    rule = InertiaRouteReturnsJsonResponseRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("GET", "users", "UserController", "index")])
    mixed = (
        "<?php\n"
        "if ($request->wantsJson()) {\n"
        "    return response()->json($users);\n"
        "}\n"
        "return Inertia::render('Users/Index', ['users' => $users]);"
    )
    assert rule.analyze_regex("app/Http/Controllers/UserController.php", mixed, facts) == []


def test_route_returns_json_response_skips_non_controller():
    rule = InertiaRouteReturnsJsonResponseRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("GET", "users", "UserController", "index")])
    assert rule.analyze_regex("app/Services/UserService.php", "<?php return response()->json($data);", facts) == []


# ==============================================================================
# Rule 3: inertia-api-route-returns-inertia
# ==============================================================================

def test_api_route_returns_inertia_valid_json():
    rule = InertiaApiRouteReturnsInertiaRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("GET", "api/users", "UserController", "index")])
    valid = "<?php $users = User::all(); return response()->json($users);"
    assert rule.analyze_regex("app/Http/Controllers/UserController.php", valid, facts) == []


def test_api_route_returns_inertia_near_miss_no_inertia():
    rule = InertiaApiRouteReturnsInertiaRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("GET", "api/users", "UserController", "index")])
    near_miss = "<?php $users = User::all(); return view('users.index', compact('users'));"
    assert rule.analyze_regex("app/Http/Controllers/UserController.php", near_miss, facts) == []


def test_api_route_returns_inertia_invalid():
    rule = InertiaApiRouteReturnsInertiaRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("GET", "api/users", "UserController", "index")])
    invalid = "<?php $users = User::all(); return Inertia::render('Users/Index', ['users' => $users]);"
    findings = rule.analyze_regex("app/Http/Controllers/UserController.php", invalid, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "inertia-api-route-returns-inertia"


def test_api_route_returns_inertia_skips_web_route():
    rule = InertiaApiRouteReturnsInertiaRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("GET", "users", "UserController", "index")])
    content = "<?php return Inertia::render('Users/Index', ['users' => $users]);"
    assert rule.analyze_regex("app/Http/Controllers/UserController.php", content, facts) == []


def test_api_route_returns_inertia_skips_wants_json():
    rule = InertiaApiRouteReturnsInertiaRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("GET", "api/users", "UserController", "index")])
    mixed = (
        "<?php\n"
        "if ($request->wantsJson()) {\n"
        "    return response()->json($users);\n"
        "}\n"
        "return Inertia::render('Users/Index', ['users' => $users]);"
    )
    assert rule.analyze_regex("app/Http/Controllers/UserController.php", mixed, facts) == []


def test_api_route_returns_inertia_skips_api_method_name():
    rule = InertiaApiRouteReturnsInertiaRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("GET", "api/users", "UserController", "index")])
    content = (
        "<?php\n"
        "public function apiIndex()\n"
        "{\n"
        "    return Inertia::render('Users/Index', ['users' => $users]);\n"
        "}"
    )
    assert rule.analyze_regex("app/Http/Controllers/UserController.php", content, facts) == []


def test_api_route_returns_inertia_skips_non_controller():
    rule = InertiaApiRouteReturnsInertiaRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("GET", "api/users", "UserController", "index")])
    assert rule.analyze_regex("app/Services/UserService.php", "<?php return Inertia::render('test');", facts) == []


# ==============================================================================
# Rule 1 (new): inertia-hybrid-controller
# ==============================================================================

def test_hybrid_controller_valid_only_inertia():
    rule = InertiaHybridControllerRule(RuleConfig(thresholds={}))
    facts = _facts()
    valid = "<?php return Inertia::render('Users/Index', ['users' => $users]);"
    assert rule.analyze_regex("app/Http/Controllers/UserController.php", valid, facts) == []


def test_hybrid_controller_valid_only_blade():
    rule = InertiaHybridControllerRule(RuleConfig(thresholds={}))
    facts = _facts()
    valid = "<?php return view('users.index', compact('users'));"
    assert rule.analyze_regex("app/Http/Controllers/UserController.php", valid, facts) == []


def test_hybrid_controller_invalid_both():
    rule = InertiaHybridControllerRule(RuleConfig(thresholds={}))
    facts = _facts()
    invalid = (
        "<?php\n"
        "class UserController extends Controller\n"
        "{\n"
        "    public function index()\n"
        "    {\n"
        "        return Inertia::render('Users/Index', ['users' => User::all()]);\n"
        "    }\n\n"
        "    public function export()\n"
        "    {\n"
        "        return view('users.export', ['users' => User::all()]);\n"
        "    }\n"
        "}"
    )
    findings = rule.analyze_regex("app/Http/Controllers/UserController.php", invalid, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "inertia-hybrid-controller"


def test_hybrid_controller_skips_abstract_class():
    rule = InertiaHybridControllerRule(RuleConfig(thresholds={}))
    facts = _facts()
    content = (
        "<?php\n"
        "abstract class BaseController extends Controller\n"
        "{\n"
        "    protected function renderPage($view, $data)\n"
        "    {\n"
        "        if (config('app.use_inertia')) {\n"
        "            return Inertia::render($view, $data);\n"
        "        }\n"
        "        return view($view, $data);\n"
        "    }\n"
        "}"
    )
    assert rule.analyze_regex("app/Http/Controllers/BaseController.php", content, facts) == []


def test_hybrid_controller_skips_admin_path():
    rule = InertiaHybridControllerRule(RuleConfig(thresholds={}))
    facts = _facts()
    content = (
        "<?php\n"
        "return Inertia::render('Dashboard');\n"
        "return view('admin.settings');"
    )
    assert rule.analyze_regex("app/Http/Controllers/Admin/SettingsController.php", content, facts) == []


# ==============================================================================
# Rule 2 (new): inertia-post-returns-render
# ==============================================================================

def _write_temp_controller(content: str, filename: str = "UserController.php") -> str:
    tmpdir = tempfile.mkdtemp()
    filepath = os.path.join(tmpdir, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    return filepath


def _method_with_file(class_name: str, name: str, file_path: str, content: str = "", line_start: int = 1, line_end: int | None = None) -> MethodInfo:
    if line_end is None:
        line_end = max(line_start, content.count("\n") + 1) if content else line_start + 19
    return MethodInfo(
        name=name,
        class_name=class_name,
        class_fqcn=f"App\\Http\\Controllers\\{class_name}",
        file_path=file_path,
        file_hash="fixture",
        line_start=line_start,
        line_end=line_end,
        call_sites=[],
    )


def test_post_returns_render_valid_get_render():
    rule = InertiaPostReturnsRenderRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("GET", "users", "UserController", "index")])
    content = "<?php return Inertia::render('Users/Index');"
    filepath = _write_temp_controller(content)
    facts.methods = [_method_with_file("UserController", "index", filepath, content=content)]
    try:
        findings = rule.analyze(facts)
        assert len(findings) == 0
    finally:
        os.remove(filepath)
        os.rmdir(os.path.dirname(filepath))


def test_post_returns_render_valid_post_redirect():
    rule = InertiaPostReturnsRenderRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("POST", "users", "UserController", "store")])
    content = "<?php User::create($data); return redirect()->route('users.index');"
    filepath = _write_temp_controller(content)
    facts.methods = [_method_with_file("UserController", "store", filepath, content=content)]
    try:
        findings = rule.analyze(facts)
        assert len(findings) == 0
    finally:
        os.remove(filepath)
        os.rmdir(os.path.dirname(filepath))


def test_post_returns_render_invalid():
    rule = InertiaPostReturnsRenderRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("POST", "users", "UserController", "store")])
    content = "<?php $user = User::create($data); return Inertia::render('Users/Show', ['user' => $user]);"
    filepath = _write_temp_controller(content)
    facts.methods = [_method_with_file("UserController", "store", filepath, content=content)]
    try:
        findings = rule.analyze(facts)
        assert len(findings) == 1
        assert findings[0].rule_id == "inertia-post-returns-render"
    finally:
        os.remove(filepath)
        os.rmdir(os.path.dirname(filepath))


def test_post_returns_render_near_miss_has_redirect():
    rule = InertiaPostReturnsRenderRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("POST", "users", "UserController", "store")])
    content = (
        "<?php\n"
        "$validated = $request->validate(['name' => 'required']);\n"
        "try {\n"
        "    User::create($validated);\n"
        "    return redirect()->route('users.index');\n"
        "} catch (\\Exception $e) {\n"
        "    return Inertia::render('Users/Create', ['error' => $e->getMessage()]);\n"
        "}\n"
    )
    filepath = _write_temp_controller(content)
    facts.methods = [_method_with_file("UserController", "store", filepath, content=content)]
    try:
        findings = rule.analyze(facts)
        assert len(findings) == 0
    finally:
        os.remove(filepath)
        os.rmdir(os.path.dirname(filepath))


def test_post_returns_render_skips_api_route():
    rule = InertiaPostReturnsRenderRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("POST", "api/users", "UserController", "store")])
    content = "<?php return Inertia::render('Users/Show');"
    filepath = _write_temp_controller(content)
    facts.methods = [_method_with_file("UserController", "store", filepath, content=content)]
    try:
        findings = rule.analyze(facts)
        assert len(findings) == 0
    finally:
        os.remove(filepath)
        os.rmdir(os.path.dirname(filepath))


def test_post_returns_render_skips_api_method_name():
    rule = InertiaPostReturnsRenderRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("POST", "users", "UserController", "apiStore")])
    content = "<?php public function apiStore() { return Inertia::render('Users/Show'); }"
    filepath = _write_temp_controller(content)
    facts.methods = [_method_with_file("UserController", "apiStore", filepath, content=content)]
    try:
        findings = rule.analyze(facts)
        assert len(findings) == 0
    finally:
        os.remove(filepath)
        os.rmdir(os.path.dirname(filepath))


# ==============================================================================
# Rule 3 (new): inertia-session-flash-on-api
# ==============================================================================

def test_session_flash_on_api_valid_json_response():
    rule = InertiaSessionFlashOnApiRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("GET", "api/users", "UserController", "index")])
    content = "<?php return response()->json(User::all());"
    filepath = _write_temp_controller(content)
    facts.methods = [_method_with_file("UserController", "index", filepath, content=content)]
    try:
        findings = rule.analyze(facts)
        assert len(findings) == 0
    finally:
        os.remove(filepath)
        os.rmdir(os.path.dirname(filepath))


def test_session_flash_on_api_valid_session_read_only():
    rule = InertiaSessionFlashOnApiRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("GET", "api/users", "UserController", "index")])
    content = "<?php $locale = session()->get('locale', 'en'); return response()->json(['locale' => $locale]);"
    filepath = _write_temp_controller(content)
    facts.methods = [_method_with_file("UserController", "index", filepath, content=content)]
    try:
        findings = rule.analyze(facts)
        assert len(findings) == 0
    finally:
        os.remove(filepath)
        os.rmdir(os.path.dirname(filepath))


def test_session_flash_on_api_invalid():
    rule = InertiaSessionFlashOnApiRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("POST", "api/users", "UserController", "store")])
    content = "<?php $user = User::create($data); session()->flash('success', 'User created'); return response()->json($user);"
    filepath = _write_temp_controller(content)
    facts.methods = [_method_with_file("UserController", "store", filepath, content=content)]
    try:
        findings = rule.analyze(facts)
        assert len(findings) == 1
        assert findings[0].rule_id == "inertia-session-flash-on-api"
    finally:
        os.remove(filepath)
        os.rmdir(os.path.dirname(filepath))


def test_session_flash_on_api_near_miss_web_route():
    rule = InertiaSessionFlashOnApiRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("POST", "users", "UserController", "store")])
    content = "<?php $user = User::create($data); session()->flash('success', 'User created'); return redirect()->route('users.index');"
    filepath = _write_temp_controller(content)
    facts.methods = [_method_with_file("UserController", "store", filepath, content=content)]
    try:
        findings = rule.analyze(facts)
        assert len(findings) == 0
    finally:
        os.remove(filepath)
        os.rmdir(os.path.dirname(filepath))


def test_session_flash_on_api_skips_sanctum():
    rule = InertiaSessionFlashOnApiRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("POST", "api/tokens", "TokenController", "create")])
    content = "<?php $token = $user->createToken('mobile'); session()->put('last_token', $token->plainTextToken); return response()->json(['token' => $token->plainTextToken]);"
    filepath = _write_temp_controller(content)
    facts.methods = [_method_with_file("TokenController", "create", filepath, content=content)]
    try:
        findings = rule.analyze(facts)
        assert len(findings) == 0
    finally:
        os.remove(filepath)
        os.rmdir(os.path.dirname(filepath))


def test_session_flash_on_api_skips_different_method():
    rule = InertiaSessionFlashOnApiRule(RuleConfig(thresholds={}))
    facts = _facts(
        routes=[_route("POST", "api/users", "UserController", "store")],
    )
    content = (
        "<?php\n"
        "class UserController extends Controller\n"
        "{\n"
        "    public function store()\n"
        "    {\n"
        "        return response()->json(User::create(request()->all()));\n"
        "    }\n\n"
        "    public function webStore()\n"
        "    {\n"
        "        session()->flash('success', 'Created');\n"
        "        return redirect()->route('users.index');\n"
        "    }\n"
        "}\n"
    )
    filepath = _write_temp_controller(content)
    facts.methods = [_method_with_file("UserController", "store", filepath, content=content, line_start=4, line_end=7)]
    try:
        findings = rule.analyze(facts)
        assert len(findings) == 0
    finally:
        os.remove(filepath)
        os.rmdir(os.path.dirname(filepath))


# ==============================================================================
# Rule 4 (new): inertia-get-with-side-effects
# ==============================================================================

def test_get_side_effects_valid_get_read():
    rule = InertiaGetWithSideEffectsRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("GET", "users", "UserController", "index")])
    content = "<?php return Inertia::render('Users/Index', ['users' => User::all()]);"
    filepath = _write_temp_controller(content)
    facts.methods = [_method_with_file("UserController", "index", filepath, content=content)]
    try:
        findings = rule.analyze(facts)
        assert len(findings) == 0
    finally:
        os.remove(filepath)
        os.rmdir(os.path.dirname(filepath))


def test_get_side_effects_valid_post_write():
    rule = InertiaGetWithSideEffectsRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("POST", "users", "UserController", "store")])
    content = "<?php User::create(request()->all()); return redirect()->route('users.index');"
    filepath = _write_temp_controller(content)
    facts.methods = [_method_with_file("UserController", "store", filepath, content=content)]
    try:
        findings = rule.analyze(facts)
        assert len(findings) == 0
    finally:
        os.remove(filepath)
        os.rmdir(os.path.dirname(filepath))


def test_get_side_effects_invalid():
    rule = InertiaGetWithSideEffectsRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("GET", "users/{user}/track", "UserController", "track")])
    content = "<?php $user->update(['last_viewed_at' => now()]); return Inertia::render('Users/Show', ['user' => $user]);"
    filepath = _write_temp_controller(content)
    facts.methods = [_method_with_file("UserController", "track", filepath, content=content)]
    try:
        findings = rule.analyze(facts)
        assert len(findings) == 1
        assert findings[0].rule_id == "inertia-get-with-side-effects"
    finally:
        os.remove(filepath)
        os.rmdir(os.path.dirname(filepath))


def test_get_side_effects_near_miss_cache_only():
    rule = InertiaGetWithSideEffectsRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("GET", "users", "UserController", "index")])
    content = "<?php $users = Cache::remember('users', 3600, fn() => User::all()); return Inertia::render('Users/Index', ['users' => $users]);"
    filepath = _write_temp_controller(content)
    facts.methods = [_method_with_file("UserController", "index", filepath, content=content)]
    try:
        findings = rule.analyze(facts)
        assert len(findings) == 0
    finally:
        os.remove(filepath)
        os.rmdir(os.path.dirname(filepath))


def test_get_side_effects_skips_different_method():
    rule = InertiaGetWithSideEffectsRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("GET", "users", "UserController", "index")])
    content = (
        "<?php\n"
        "class UserController extends Controller\n"
        "{\n"
        "    public function index()\n"
        "    {\n"
        "        return Inertia::render('Users/Index', ['users' => User::all()]);\n"
        "    }\n\n"
        "    public function store()\n"
        "    {\n"
        "        User::create(request()->all());\n"
        "        return redirect()->route('users.index');\n"
        "    }\n"
        "}\n"
    )
    filepath = _write_temp_controller(content)
    facts.methods = [_method_with_file("UserController", "index", filepath, content=content, line_start=4, line_end=7)]
    try:
        findings = rule.analyze(facts)
        assert len(findings) == 0
    finally:
        os.remove(filepath)
        os.rmdir(os.path.dirname(filepath))


def test_get_side_effects_skips_api_route():
    rule = InertiaGetWithSideEffectsRule(RuleConfig(thresholds={}))
    facts = _facts(routes=[_route("GET", "api/users/{user}/track", "UserController", "track")])
    content = "<?php $user->update(['last_viewed_at' => now()]); return response()->json($user);"
    filepath = _write_temp_controller(content)
    facts.methods = [_method_with_file("UserController", "track", filepath, content=content)]
    try:
        findings = rule.analyze(facts)
        assert len(findings) == 0
    finally:
        os.remove(filepath)
        os.rmdir(os.path.dirname(filepath))
