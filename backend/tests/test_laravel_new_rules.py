from __future__ import annotations

from schemas.facts import ClassInfo, Facts, RouteInfo
from rules.laravel.business_logic_in_migration import BusinessLogicInMigrationRule
from rules.laravel.cache_stampede_risk import CacheStampedeRiskRule
from rules.laravel.chunk_missing_for_large_datasets import ChunkMissingForLargeDatasetsRule
from rules.laravel.date_format_missing_cast import DateFormatMissingCastRule
from rules.laravel.hardcoded_magic_strings import HardcodedMagicStringsRule
from rules.laravel.laravel_naming_conventions import LaravelNamingConventionsRule
from rules.laravel.missing_circuit_breaker import MissingCircuitBreakerRule
from rules.laravel.missing_domain_event import MissingDomainEventRule
from rules.laravel.missing_health_check_endpoint import MissingHealthCheckEndpointRule
from rules.laravel.missing_model_factory import MissingModelFactoryRule
from rules.laravel.service_provider_heavy_boot import ServiceProviderHeavyBootRule
from rules.laravel.synchronous_mail_in_request import SynchronousMailInRequestRule
from rules.laravel.test_no_database_trait import TestNoDatabaseTraitRule


def _facts() -> Facts:
    return Facts(project_path=".")


def _route(uri: str) -> RouteInfo:
    return RouteInfo(method="GET", uri=uri, file_path="routes/web.php", line_number=10)


def _model(name: str, *, extends: str | None = "Model", abstract: bool = False) -> ClassInfo:
    return ClassInfo(name=name, fqcn=f"App\\Models\\{name}", file_path=f"app/Models/{name}.php", file_hash="fixture", extends=extends, is_abstract=abstract, line_start=5)


def test_cache_stampede_risk_valid_invalid_fp_guard():
    rule = CacheStampedeRiskRule()
    valid = "<?php\nCache::lock('report-lock')->get(fn() => Cache::remember('report', 3600, fn() => heavyQuery()));"
    invalid = "<?php\n$value = Cache::remember('report', 3600, fn() => heavyQuery());"
    fp_guard = "<?php\nCache::lock('report-lock');\n$value = Cache::remember('report', 3600, fn() => heavyQuery());"

    assert rule.analyze_regex("app/Services/ReportService.php", valid, _facts()) == []
    assert len(rule.analyze_regex("app/Services/ReportService.php", invalid, _facts())) == 1
    assert rule.analyze_regex("app/Services/ReportService.php", fp_guard, _facts()) == []


def test_synchronous_mail_in_request_valid_invalid_fp_guard():
    rule = SynchronousMailInRequestRule()
    valid = "<?php\nMail::to($user)->queue(new WelcomeMail($user));"
    invalid = "<?php\nMail::to($user)->send(new WelcomeMail($user));"
    fp_guard = "<?php\nMail::to($user)->send(new WelcomeMail($user));"

    assert rule.analyze_regex("app/Http/Controllers/UserController.php", valid, _facts()) == []
    assert len(rule.analyze_regex("app/Http/Controllers/UserController.php", invalid, _facts())) == 1
    assert rule.analyze_regex("database/seeders/UserSeeder.php", fp_guard, _facts()) == []


def test_service_provider_heavy_boot_valid_invalid_fp_guard():
    rule = ServiceProviderHeavyBootRule()
    valid = "<?php\nclass AppServiceProvider { public function boot(): void { View::share('x', 'y');\n    } }"
    invalid = "<?php\nclass AppServiceProvider { public function boot(): void {\n$settings = DB::table('settings')->get();\n    } }"
    fp_guard = "<?php\nclass AppServiceProvider { public function boot(): void {\n$this->app->singleton(Settings::class, fn() => DB::table('settings')->get());\n    } }"

    assert rule.analyze_regex("app/Providers/AppServiceProvider.php", valid, _facts()) == []
    assert len(rule.analyze_regex("app/Providers/AppServiceProvider.php", invalid, _facts())) == 1
    assert rule.analyze_regex("app/Providers/AppServiceProvider.php", fp_guard, _facts()) == []


def test_business_logic_in_migration_valid_invalid_fp_guard():
    rule = BusinessLogicInMigrationRule()
    valid = "<?php\nreturn new class { public function up(): void {\nSchema::table('users', fn($table) => $table->string('role'));\n    } };"
    invalid = "<?php\nuse App\\Models\\User;\nreturn new class { public function up(): void {\nforeach (User::all() as $user) { $user->update(['role' => 'user']); }\n    } };"
    fp_guard = "<?php\nreturn new class { public function down(): void {\nSchema::dropIfExists('users');\n    } };"

    assert rule.analyze_regex("database/migrations/2026_01_01_000000_add_role.php", valid, _facts()) == []
    assert len(rule.analyze_regex("database/migrations/2026_01_01_000000_backfill_users.php", invalid, _facts())) == 1
    assert rule.analyze_regex("database/migrations/2026_01_01_000000_drop_old.php", fp_guard, _facts()) == []


def test_missing_health_check_endpoint_valid_invalid_fp_guard():
    rule = MissingHealthCheckEndpointRule()
    valid = _facts(); valid.routes = [_route("/health")]
    invalid = _facts(); invalid.routes = [_route("/dashboard")]
    fp_guard = _facts(); fp_guard.files = ["composer/spatie/laravel-health"]
    api_prefixed = _facts(); api_prefixed.routes = [_route("/api/health")]

    assert rule.analyze(valid) == []
    assert rule.analyze(api_prefixed) == []
    assert len(rule.analyze(invalid)) == 1
    assert rule.analyze(fp_guard) == []


def test_missing_health_check_endpoint_accepts_express_health_route(tmp_path):
    root = tmp_path / "node-api"
    route_file = root / "src" / "api" / "routes" / "health.routes.js"
    route_file.parent.mkdir(parents=True)
    route_file.write_text(
        "const router = require('express').Router();\nrouter.get('/health', (_req, res) => res.json({ ok: true }));\n",
        encoding="utf-8",
    )
    facts = _facts()
    facts.project_path = str(root)
    facts.files = ["src/api/routes/health.routes.js"]

    assert MissingHealthCheckEndpointRule().analyze(facts) == []


def test_missing_model_factory_valid_invalid_fp_guard():
    rule = MissingModelFactoryRule()
    valid = _facts(); valid.models = [_model("Product")]; valid.files = ["database/factories/ProductFactory.php"]
    invalid = _facts(); invalid.models = [_model("Product")]; invalid.files = []
    fp_guard = _facts(); fp_guard.models = [_model("RoleUser", extends="Pivot")]; fp_guard.files = []

    assert rule.analyze(valid) == []
    assert len(rule.analyze(invalid)) == 1
    assert rule.analyze(fp_guard) == []


def test_test_no_database_trait_valid_invalid_fp_guard():
    rule = TestNoDatabaseTraitRule()
    valid = "<?php\nclass UserTest extends TestCase { use RefreshDatabase; public function test_create() { User::create([]); } }"
    invalid = "<?php\nclass UserTest extends TestCase { public function test_create() { User::create([]); } }"
    fp_guard = "<?php\nclass UserTest extends TestCase { public function test_view() { $this->get('/'); } }"

    assert rule.analyze_regex("tests/Feature/UserTest.php", valid, _facts()) == []
    assert len(rule.analyze_regex("tests/Feature/UserTest.php", invalid, _facts())) == 1
    assert rule.analyze_regex("tests/Feature/UserTest.php", fp_guard, _facts()) == []


def test_missing_circuit_breaker_valid_invalid_fp_guard():
    rule = MissingCircuitBreakerRule()
    valid = "<?php\nHttp::timeout(5)->retry(2)->post('https://api.test', $data);"
    invalid = "<?php\nHttp::post('https://api.test', $data);"
    fp_guard = "<?php\ntry {\nHttp::get('https://api.test');\n} catch (Throwable $e) { report($e); }"

    assert rule.analyze_regex("app/Services/PaymentService.php", valid, _facts()) == []
    assert len(rule.analyze_regex("app/Services/PaymentService.php", invalid, _facts())) == 1
    assert rule.analyze_regex("app/Services/PaymentService.php", fp_guard, _facts()) == []


def test_missing_domain_event_valid_invalid_fp_guard():
    rule = MissingDomainEventRule()
    valid = "<?php\n$order->save(); OrderPlaced::dispatch($order);"
    invalid = "<?php\n$order->save();"
    fp_guard = "<?php\nclass OrderTest { public function test_save() { $order->save(); } }"

    assert rule.analyze_regex("app/Services/CheckoutService.php", valid, _facts()) == []
    assert len(rule.analyze_regex("app/Services/CheckoutService.php", invalid, _facts())) == 1
    assert rule.analyze_regex("tests/Feature/OrderTest.php", fp_guard, _facts()) == []


def test_chunk_missing_for_large_datasets_valid_invalid_fp_guard():
    rule = ChunkMissingForLargeDatasetsRule()
    valid = "<?php\nUser::chunk(500, fn($users) => $users->each(fn($user) => process($user)));"
    invalid = "<?php\nforeach (User::all() as $user) { process($user); }"
    fp_guard = "<?php\nforeach (User::all() as $user) { process($user); }"

    assert rule.analyze_regex("app/Jobs/SyncUsers.php", valid, _facts()) == []
    assert len(rule.analyze_regex("app/Jobs/SyncUsers.php", invalid, _facts())) == 1
    assert rule.analyze_regex("tests/Feature/UserSyncTest.php", fp_guard, _facts()) == []


def test_laravel_naming_conventions_valid_invalid_fp_guard():
    rule = LaravelNamingConventionsRule()
    valid = "<?php\nclass UserController extends Controller {}\nclass Article extends Model { public function comments(): HasMany { return $this->hasMany(Comment::class); } }"
    invalid = "<?php\nclass UsersController extends Controller {}"
    fp_guard = "<?php\nclass SettingsController extends Controller {}"

    assert rule.analyze_regex("app/Http/Controllers/UserController.php", valid, _facts()) == []
    assert len(rule.analyze_regex("app/Http/Controllers/UsersController.php", invalid, _facts())) == 1
    assert rule.analyze_regex("app/Http/Controllers/SettingsController.php", fp_guard, _facts()) == []


def test_hardcoded_magic_strings_valid_invalid_fp_guard():
    rule = HardcodedMagicStringsRule()
    valid = "<?php\n$status = UserStatus::ACTIVE;"
    invalid = "<?php\nif ($a === 'admin') {} if ($b === 'admin') {} if ($c === 'admin') {}"
    fp_guard = "<?php\nif ($a === 'auth.login') {} if ($b === 'auth.login') {} if ($c === 'auth.login') {}"

    assert rule.analyze_regex("app/Services/AuthService.php", valid, _facts()) == []
    assert len(rule.analyze_regex("app/Services/AuthService.php", invalid, _facts())) == 1
    assert rule.analyze_regex("app/Services/AuthService.php", fp_guard, _facts()) == []


def test_date_format_missing_cast_valid_invalid_fp_guard():
    rule = DateFormatMissingCastRule()
    valid = "<?php\nprotected $casts = ['ordered_at' => 'datetime'];\npublic function label() { return $this->ordered_at->format('Y-m-d'); }"
    invalid = "{{ Carbon::createFromFormat('Y-d-m', $order->ordered_at)->toDateString() }}"
    fp_guard = "<?php\nprotected $casts = ['published_at' => 'datetime'];"

    assert rule.analyze_regex("app/Models/Order.php", valid, _facts()) == []
    assert len(rule.analyze_regex("resources/views/orders/show.blade.php", invalid, _facts())) == 1
    assert rule.analyze_regex("app/Models/Post.php", fp_guard, _facts()) == []
