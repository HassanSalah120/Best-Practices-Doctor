from __future__ import annotations

from pathlib import Path

from schemas.facts import Facts, RouteInfo
from rules.laravel.api_response_inconsistent_shape import ApiResponseInconsistentShapeRule
from rules.laravel.blade_component_no_fallback_slot import BladeComponentNoFallbackSlotRule
from rules.laravel.eloquent_raw_where_string import EloquentRawWhereStringRule
from rules.laravel.missing_api_rate_limit_headers import MissingApiRateLimitHeadersRule
from rules.laravel.missing_feature_flag_pattern import MissingFeatureFlagPatternRule
from rules.laravel.missing_model_observer_registration import MissingModelObserverRegistrationRule
from rules.laravel.no_pagination_on_relationship import NoPaginationOnRelationshipRule
from rules.php.catch_too_broad import CatchTooBroadRule
from rules.php.missing_return_type_nullable import MissingReturnTypeNullableRule
from rules.react.console_log_in_production_code import ConsoleLogInProductionCodeRule
from rules.react.inertia_page_missing_error_boundary import InertiaPageMissingErrorBoundaryRule
from rules.react.useless_suspense_boundary import UselessSuspenseBoundaryRule


def _facts(root: Path) -> Facts:
    files = [path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()]
    return Facts(project_path=str(root), files=files)


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_missing_api_rate_limit_headers_cases(tmp_path: Path) -> None:
    rule = MissingApiRateLimitHeadersRule()
    facts = Facts(
        project_path=str(tmp_path),
        routes=[RouteInfo(method="GET", uri="api/users", middleware=["api", "throttle:api"], file_path="routes/api.php", line_number=3)],
    )
    assert len(rule.analyze(facts)) == 1

    facts.routes[0].middleware = ["api"]
    assert rule.analyze(facts) == []

    _write(tmp_path, "app/Http/Middleware/RateHeaders.php", "<?php return $response->header('X-RateLimit-Remaining', 1);")
    facts.routes[0].middleware = ["api", "throttle:api"]
    facts.files = ["app/Http/Middleware/RateHeaders.php"]
    assert rule.analyze(facts) == []


def test_eloquent_raw_where_string_cases() -> None:
    rule = EloquentRawWhereStringRule()
    facts = Facts(project_path=".")
    assert len(rule.analyze_regex("app/Repo.php", "<?php User::query()->where('status = ' . $status)->get();", facts)) == 1
    assert len(rule.analyze_regex("app/Repo.php", '<?php User::query()->where("user_id = $userId")->get();', facts)) == 1
    assert rule.analyze_regex("app/Repo.php", "<?php User::query()->where('status', $status)->get();", facts) == []
    assert rule.analyze_regex("app/Repo.php", "<?php User::query()->whereRaw('status = ?', [$status])->get();", facts) == []


def test_missing_model_observer_registration_cases(tmp_path: Path) -> None:
    rule = MissingModelObserverRegistrationRule()
    missing = tmp_path / "observer_missing"
    _write(missing, "app/Observers/OrderObserver.php", "<?php class OrderObserver { public function created($order) {} }")
    assert len(rule.analyze(_facts(missing))) == 1

    registered = tmp_path / "observer_registered"
    _write(registered, "app/Observers/OrderObserver.php", "<?php class OrderObserver { public function created($order) {} }")
    _write(registered, "app/Providers/AppServiceProvider.php", "<?php Order::observe(OrderObserver::class);")
    assert rule.analyze(_facts(registered)) == []

    none = tmp_path / "observer_none"
    none.mkdir()
    assert rule.analyze(_facts(none)) == []


def test_blade_component_no_fallback_slot_cases() -> None:
    rule = BladeComponentNoFallbackSlotRule()
    facts = Facts(project_path=".")
    path = "resources/views/components/card.blade.php"
    assert len(rule.analyze_regex(path, "<div>{{ $slot }}</div>", facts)) == 1
    assert rule.analyze_regex(path, "@isset($slot)<div>{{ $slot }}</div>@endisset", facts) == []
    assert rule.analyze_regex("resources/views/layouts/app.blade.php", "<html>{{ $slot }}</html>", facts) == []


def test_api_response_inconsistent_shape_cases() -> None:
    rule = ApiResponseInconsistentShapeRule()
    facts = Facts(project_path=".")
    invalid = "<?php class UserController { function a(){return response()->json(['data'=>$users]);} function b(){return response()->json($users);} }"
    assert len(rule.analyze_ast("app/Http/Controllers/UserController.php", invalid, facts)) == 1

    resource_mix = "<?php class UserController { function a(){return UserResource::collection($users);} function b(){return response()->json($users);} }"
    assert len(rule.analyze_ast("app/Http/Controllers/UserController.php", resource_mix, facts)) == 1

    safe = "<?php class UserController { function a(){return response()->json(['data'=>$users]);} function b(){return response()->json(['data'=>$one]);} }"
    assert rule.analyze_ast("app/Http/Controllers/UserController.php", safe, facts) == []
    assert rule.analyze_ast("app/Http/Controllers/UserController.php", "<?php class C { function a(){return response()->json($x);} }", facts) == []


def test_no_pagination_on_relationship_cases() -> None:
    rule = NoPaginationOnRelationshipRule()
    facts = Facts(project_path=".")
    invalid = "<?php class Post { public function comments(){ return $this->hasMany(Comment::class); } public function loadAll($post){ return $post->comments()->get(); } }"
    assert len(rule.analyze_ast("app/Models/Post.php", invalid, facts)) == 1

    property_invalid = "<?php class Post { public function comments(){ return $this->hasMany(Comment::class); } public function countAll($post){ return count($post->comments); } }"
    assert len(rule.analyze_ast("app/Models/Post.php", property_invalid, facts)) == 1

    safe = "<?php class Post { public function comments(){ return $this->hasMany(Comment::class); } public function page($post){ return $post->comments()->limit(20)->get(); } }"
    assert rule.analyze_ast("app/Models/Post.php", safe, facts) == []


def test_missing_return_type_nullable_cases() -> None:
    rule = MissingReturnTypeNullableRule()
    facts = Facts(project_path=".")
    assert len(rule.analyze_regex("app/Service.php", "<?php function name(): string { return null; }", facts)) == 1
    assert len(rule.analyze_regex("app/Service.php", "<?php function countIt(): int { if(!$x){ return; } return 1; }", facts)) == 1
    assert rule.analyze_regex("app/Service.php", "<?php function name(): ?string { return null; }", facts) == []
    assert rule.analyze_regex("tests/ServiceTest.php", "<?php function name(): string { return null; }", facts) == []


def test_catch_too_broad_cases() -> None:
    rule = CatchTooBroadRule()
    facts = Facts(project_path=".")
    assert len(rule.analyze_regex("app/Service.php", "<?php try { run(); } catch (\\Throwable $e) { return false; }", facts)) == 1
    assert len(rule.analyze_regex("app/Service.php", "<?php try { run(); } catch (Exception $e) { return null; }", facts)) == 1
    safe_log = "<?php try { run(); } catch (\\Throwable $e) { report($e); return false; }"
    assert rule.analyze_regex("app/Service.php", safe_log, facts) == []
    assert rule.analyze_regex("app/Service.php", "<?php try { run(); } catch (\\Throwable $e) { throw $e; }", facts) == []


def test_console_log_in_production_code_cases() -> None:
    rule = ConsoleLogInProductionCodeRule()
    facts = Facts(project_path=".")
    assert len(rule.analyze_regex("resources/js/App.tsx", "console.log(user)", facts)) == 1
    assert len(rule.analyze_regex("resources/js/App.tsx", "console.warn(user)", facts)) == 1
    assert rule.analyze_regex("resources/js/App.test.tsx", "console.log(user)", facts) == []
    assert rule.analyze_regex("resources/js/logger.ts", "console.error(error)", facts) == []
    boundary = "class ErrorBoundary { componentDidCatch(error) { console.error(error); } }"
    assert rule.analyze_regex("resources/js/ErrorBoundary.tsx", boundary, facts) == []


def test_inertia_page_missing_error_boundary_cases() -> None:
    rule = InertiaPageMissingErrorBoundaryRule()
    facts = Facts(project_path=".")
    invalid = "import { usePage } from '@inertiajs/react'; export default function Users(){ const p = usePage(); return <main /> }"
    assert len(rule.analyze_regex("resources/js/pages/Users.tsx", invalid, facts)) == 1

    safe = "import { usePage } from '@inertiajs/react'; export default function Users(){ return <ErrorBoundary><main /></ErrorBoundary> }"
    assert rule.analyze_regex("resources/js/pages/Users.tsx", safe, facts) == []
    assert rule.analyze_regex("resources/js/layouts/AppLayout.tsx", invalid, facts) == []
    assert rule.analyze_regex("resources/js/components/Button.tsx", "export const Button = () => <button />", facts) == []


def test_useless_suspense_boundary_cases() -> None:
    rule = UselessSuspenseBoundaryRule()
    facts = Facts(project_path=".")
    assert len(rule.analyze_regex("resources/js/App.tsx", "return <Suspense fallback={null}><Profile /></Suspense>", facts)) == 1
    assert rule.analyze_regex("resources/js/App.tsx", "const Profile = React.lazy(() => import('./Profile')); return <Suspense><Profile /></Suspense>", facts) == []
    assert rule.analyze_regex("resources/js/App.tsx", "useQuery({ queryKey, queryFn, suspense: true }); return <Suspense><Profile /></Suspense>", facts) == []


def test_missing_feature_flag_pattern_cases(tmp_path: Path) -> None:
    rule = MissingFeatureFlagPatternRule()
    large = tmp_path / "large"
    _write(large, "routes/web.php", "\n".join("Route::get('/x%s', X::class);" % i for i in range(11)))
    assert len(rule.analyze(_facts(large))) == 1

    small = tmp_path / "small"
    _write(small, "routes/web.php", "Route::get('/x', X::class);")
    assert rule.analyze(_facts(small)) == []

    pennant = tmp_path / "pennant"
    _write(pennant, "routes/web.php", "\n".join("Route::get('/x%s', X::class);" % i for i in range(11)))
    _write(pennant, "composer.json", '{"require":{"laravel/pennant":"^1.0"}}')
    assert rule.analyze(_facts(pennant)) == []

    env_flags = tmp_path / "env_flags"
    _write(env_flags, "routes/web.php", "\n".join("Route::get('/x%s', X::class);" % i for i in range(11)))
    _write(env_flags, ".env.example", "FEATURE_NEW_DASHBOARD=false\n")
    assert rule.analyze(_facts(env_flags)) == []
