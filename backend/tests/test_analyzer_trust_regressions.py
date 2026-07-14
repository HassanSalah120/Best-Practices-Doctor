from __future__ import annotations

import json
from pathlib import Path

from analysis.facts_builder import FactsBuilder
from core.detector import ProjectDetector
from core.rule_engine import RUNTIME_RULES, create_engine
from core.ruleset import RuleConfig, Ruleset
from rules.laravel.error_pages_missing import ErrorPagesMissingRule
from rules.laravel.job_missing_retry_policy import JobMissingRetryPolicyRule
from rules.laravel.sensitive_data_logging import SensitiveDataLoggingRule
from rules.laravel.test_no_database_trait import TestNoDatabaseTraitRule
from rules.laravel.user_model_missing_must_verify_email import UserModelMissingMustVerifyEmailRule
from rules.php.sql_injection_risk import SqlInjectionRiskRule
from rules.react.console_log_in_production_code import ConsoleLogInProductionCodeRule
from rules.react.inertia_page_missing_error_boundary import InertiaPageMissingErrorBoundaryRule
from rules.react.inertia_form_uses_fetch import InertiaFormUsesFetchRule
from rules.react.missing_error_boundary_general import MissingErrorBoundaryGeneralRule
from rules.react.route_shell_missing_error_boundary import RouteShellMissingErrorBoundaryRule
from schemas.facts import Facts, MethodInfo, RouteInfo


def _ruleset_for(rule_id: str) -> Ruleset:
    return Ruleset(name="strict", rules={rule_id: RuleConfig(enabled=True)})


def test_laravel_absence_rule_is_not_applicable_to_native_php() -> None:
    facts = Facts(project_path=".", files=["index.php"])
    rule = ErrorPagesMissingRule(RuleConfig())

    assert rule.is_applicable(facts, "native_php") is False


def test_canonical_sql_rule_is_cross_framework_and_ignores_constant_raw_sql() -> None:
    assert RUNTIME_RULES["sql-injection-risk"] is SqlInjectionRiskRule
    rule = SqlInjectionRiskRule(RuleConfig())
    facts = Facts(
        project_path=".",
        methods=[
            MethodInfo(
                name="safe",
                class_name="QueryService",
                file_path="src/QueryService.php",
                file_hash="safe",
                call_sites=["->whereRaw('deleted_at IS NULL')"],
            ),
            MethodInfo(
                name="unsafe",
                class_name="QueryService",
                file_path="src/QueryService.php",
                file_hash="unsafe",
                call_sites=['->whereRaw("email = \'$email\'")'],
            ),
        ],
    )

    findings = rule.analyze(facts)

    assert [finding.context for finding in findings] == ["QueryService::unsafe"]
    assert rule.is_applicable(facts, "native_php") is True


def test_console_rule_ignores_comments_and_string_literals() -> None:
    rule = ConsoleLogInProductionCodeRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
// console.log('documentation example')
const example = "console.error('also not executable')";
/* console.warn('block comment') */
console.info(value);
"""

    findings = rule.analyze_regex("src/App.tsx", content, facts)

    assert len(findings) == 1
    assert findings[0].line_start == 5


def test_detector_supports_nested_manifests_and_nonstandard_react_root(tmp_path: Path) -> None:
    backend = tmp_path / "apps" / "api"
    frontend = tmp_path / "apps" / "web" / "client"
    backend.mkdir(parents=True)
    frontend.mkdir(parents=True)
    (backend / "composer.json").write_text(
        json.dumps({"require": {"laravel/framework": "^12.0"}}),
        encoding="utf-8",
    )
    (frontend.parent / "package.json").write_text(
        json.dumps({"dependencies": {"react": "^19.0.0"}}),
        encoding="utf-8",
    )
    (frontend / "App.tsx").write_text("export default function App(){ return <main />; }", encoding="utf-8")

    info = ProjectDetector(tmp_path).detect()

    assert info.project_type.value == "laravel_blade"
    assert info.has_react_components is True
    assert "react" in info.features


def test_custom_route_location_is_detected_and_parsed(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text(
        json.dumps({"require": {"laravel/framework": "^12.0"}}),
        encoding="utf-8",
    )
    route_file = tmp_path / "app" / "routing" / "public_api.php"
    route_file.parent.mkdir(parents=True)
    route_file.write_text(
        "<?php Route::post('/api/orders', [OrderEndpoint::class, 'store']);",
        encoding="utf-8",
    )

    info = ProjectDetector(tmp_path).detect()
    facts = FactsBuilder(info).build()

    assert info.has_api_routes is True
    assert info.project_type.value == "laravel_api"
    assert [(route.method, route.uri) for route in facts.routes] == [("POST", "/api/orders")]


def test_fact_based_inertia_rule_runs_through_engine_with_relative_paths(tmp_path: Path) -> None:
    controller = tmp_path / "src" / "Http" / "UserController.php"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        """<?php
class UserController {
    public function show() {
        User::update(['last_seen_at' => now()]);
        return Inertia::render('Users/Show');
    }
}
""",
        encoding="utf-8",
    )
    facts = Facts(
        project_path=str(tmp_path),
        files=["src/Http/UserController.php"],
        routes=[
            RouteInfo(
                method="GET",
                uri="users/{user}",
                controller="UserController",
                action="show",
                file_path="app/routing/web.php",
            ),
        ],
        methods=[
            MethodInfo(
                name="show",
                class_name="UserController",
                file_path="src/Http/UserController.php",
                file_hash="controller",
                line_start=3,
                line_end=6,
            ),
        ],
    )
    facts.project_context.project_type = "laravel_inertia_react"
    engine = create_engine(
        ruleset=_ruleset_for("inertia-get-with-side-effects"),
        selected_rules=["inertia-get-with-side-effects"],
    )

    result = engine.run(facts, project_type="laravel_inertia_react")

    assert [finding.rule_id for finding in result.findings] == ["inertia-get-with-side-effects"]


def test_react_rule_uses_laravel_business_context_fallback() -> None:
    facts = Facts(project_path=".")
    facts.project_context.project_type = "internal_admin_system"
    facts.project_context.project_business_context = "internal_admin_system"
    facts.project_context.project_business_confidence = 1.0
    facts.project_context.project_business_confidence_kind = "structural"
    facts.project_context.project_business_source = "explicit"
    engine = create_engine(
        ruleset=_ruleset_for("canonical-missing-or-invalid"),
        selected_rules=["canonical-missing-or-invalid"],
    )

    engine._apply_context_calibration(facts)

    assert engine.get_rule("canonical-missing-or-invalid").enabled is False


def test_email_verification_rule_resolves_configured_renamed_auth_model(tmp_path: Path) -> None:
    config = tmp_path / "config" / "auth.php"
    config.parent.mkdir(parents=True)
    config.write_text(
        "<?php return ['providers' => ['users' => ['model' => Domain\\Identity\\Account::class]]];",
        encoding="utf-8",
    )
    facts = Facts(
        project_path=str(tmp_path),
        files=["config/auth.php", "src/Domain/Identity/Account.php"],
        routes=[
            RouteInfo(
                method="GET",
                uri="account",
                middleware=["auth", "verified"],
                file_path="app/routing/web.php",
            ),
        ],
    )
    content = """
<?php
use Illuminate\\Foundation\\Auth\\User as Authenticatable;
class Account extends Authenticatable {}
"""

    findings = UserModelMissingMustVerifyEmailRule(RuleConfig()).analyze_regex(
        "src/Domain/Identity/Account.php",
        content,
        facts,
    )

    assert len(findings) == 1
    assert findings[0].context == "Account"


def test_global_error_boundary_suppresses_per_page_boundary_findings(tmp_path: Path) -> None:
    entry = tmp_path / "client" / "bootstrap.tsx"
    shell = tmp_path / "client" / "shells" / "RootExperience.tsx"
    page = tmp_path / "client" / "pages" / "Orders.tsx"
    entry.parent.mkdir(parents=True)
    shell.parent.mkdir(parents=True)
    page.parent.mkdir(parents=True)

    entry.write_text(
        "import { createRoot } from 'react-dom/client';\n"
        "import RootExperience from './shells/RootExperience';\n"
        "createRoot(document.getElementById('root')!).render(<RootExperience />);\n",
        encoding="utf-8",
    )
    shell.write_text(
        "import { ErrorBoundary } from '../components/ErrorBoundary';\n"
        "export default function RootExperience() {\n"
        "  return (<ErrorBoundary><RouterProvider router={router} /></ErrorBoundary>);\n"
        "}\n",
        encoding="utf-8",
    )
    page_source = (
        "import { usePage } from '@inertiajs/react';\n"
        "export default function Orders() {\n"
        "  const data = usePage();\n"
        "  const first = useQuery({ queryKey: ['orders'] });\n"
        "  const second = fetch('/orders');\n"
        "  return (<main><table><tbody>{String(data)}</tbody></table></main>);\n"
        "}\n"
        + "// data-heavy feature\n" * 50
    )
    page.write_text(page_source, encoding="utf-8")
    facts = Facts(
        project_path=str(tmp_path),
        files=[
            "client/bootstrap.tsx",
            "client/shells/RootExperience.tsx",
            "client/pages/Orders.tsx",
        ],
    )

    assert InertiaPageMissingErrorBoundaryRule().analyze_regex(
        "client/pages/Orders.tsx", page_source, facts,
    ) == []
    assert MissingErrorBoundaryGeneralRule().analyze_regex(
        "client/pages/Orders.tsx", page_source, facts,
    ) == []
    assert RouteShellMissingErrorBoundaryRule().analyze_regex(
        "client/pages/Orders.tsx", page_source, facts,
    ) == []


def test_native_php_entrypoint_can_live_under_public(tmp_path: Path) -> None:
    public = tmp_path / "public"
    public.mkdir()
    (public / "index.php").write_text(
        "<?php require dirname(__DIR__) . '/vendor/autoload.php';",
        encoding="utf-8",
    )

    info = ProjectDetector(tmp_path).detect()

    assert info.project_type.value == "native_php"


def test_job_rule_uses_semantics_after_job_is_relocated() -> None:
    source = """<?php
use Illuminate\\Contracts\\Queue\\ShouldQueue;
class SyncInvoice implements ShouldQueue {
    public function handle() { Http::post('/billing'); }
}
"""
    facts = Facts(project_path=".")
    rule = JobMissingRetryPolicyRule(RuleConfig())

    conventional = rule.analyze_regex("app/Jobs/SyncInvoice.php", source, facts)
    relocated = rule.analyze_regex("src/Billing/Async/SyncInvoice.php", source, facts)

    assert len(conventional) == len(relocated) == 1


def test_inertia_form_rule_only_reads_the_wired_submission_handler() -> None:
    facts = Facts(project_path=".", framework_project_type="laravel_inertia_react")
    rule = InertiaFormUsesFetchRule(RuleConfig())
    unrelated = """
export default function Checkout() {
  const track = () => fetch('/analytics');
  const submit = () => router.post('/orders');
  return <form onSubmit={submit}><button>Save</button></form>;
}
"""
    inline_submission = """
export default function Checkout() {
  return <form onSubmit={(event) => { event.preventDefault(); fetch('/orders'); }} />;
}
"""

    assert rule.analyze_regex("ui/screens/Checkout.tsx", unrelated, facts) == []
    assert len(rule.analyze_regex("ui/screens/Checkout.tsx", inline_submission, facts)) == 1


def test_sensitive_logging_ignores_examples_in_comments_and_strings() -> None:
    source = """<?php
// Log::info('password', $request->password);
$example = "Log::debug('token', $request->token)";
Log::warning('login', ['password' => $request->password]);
"""

    findings = SensitiveDataLoggingRule(RuleConfig()).analyze_regex(
        "src/Auth/Login.php",
        source,
        Facts(project_path="."),
    )

    assert len(findings) == 1
    assert findings[0].line_start == 4


def test_custom_migration_directory_is_discovered_semantically(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text(
        json.dumps({"require": {"laravel/framework": "^12.0"}}),
        encoding="utf-8",
    )
    migration = tmp_path / "modules" / "Billing" / "schema" / "CreateInvoices.php"
    migration.parent.mkdir(parents=True)
    migration.write_text(
        """<?php
return new class extends Migration {
    public function up() {
        Schema::create('invoices', function (Blueprint $table) { $table->id(); });
    }
};
""",
        encoding="utf-8",
    )

    facts = FactsBuilder(ProjectDetector(tmp_path).detect()).build()

    assert any(change.table_name == "invoices" for change in facts.migration_table_changes)


def test_request_role_requires_form_request_semantics(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text(
        json.dumps({"require": {"laravel/framework": "^12.0"}}),
        encoding="utf-8",
    )
    domain = tmp_path / "src" / "Domain"
    domain.mkdir(parents=True)
    (domain / "PurchaseRequest.php").write_text(
        "<?php class PurchaseRequest {}",
        encoding="utf-8",
    )
    (domain / "StoreOrder.php").write_text(
        "<?php class StoreOrder extends FormRequest {}",
        encoding="utf-8",
    )

    facts = FactsBuilder(ProjectDetector(tmp_path).detect()).build()
    names = {item.name for item in facts.form_requests}

    assert "StoreOrder" in names
    assert "PurchaseRequest" not in names


def test_with_routing_assigns_api_role_to_custom_route_file(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text(
        json.dumps({"require": {"laravel/framework": "^12.0"}}),
        encoding="utf-8",
    )
    bootstrap = tmp_path / "bootstrap" / "app.php"
    bootstrap.parent.mkdir(parents=True)
    bootstrap.write_text(
        "<?php Application::configure()->withRouting(api: base_path('modules/Http/endpoints.php'));",
        encoding="utf-8",
    )
    routes = tmp_path / "modules" / "Http" / "endpoints.php"
    routes.parent.mkdir(parents=True)
    routes.write_text("<?php Route::post('/orders', fn () => null);", encoding="utf-8")

    facts = FactsBuilder(ProjectDetector(tmp_path).detect()).build()

    assert len(facts.routes) == 1
    assert "api" in facts.routes[0].middleware


def test_builder_preserves_react_imports_for_context_detection(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text(
        json.dumps({"require": {"laravel/framework": "^12.0"}}),
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"react": "^19.0.0", "@inertiajs/react": "^2.0.0"}}),
        encoding="utf-8",
    )
    screen = tmp_path / "client" / "OrderScreen.tsx"
    screen.parent.mkdir()
    screen.write_text(
        "import { usePage } from '@inertiajs/react';\n"
        "export default function OrderScreen() { usePage(); return <main />; }",
        encoding="utf-8",
    )

    facts = FactsBuilder(ProjectDetector(tmp_path).detect()).build()
    imports = {item for component in facts.react_components for item in component.imports}
    context = create_engine(ruleset=_ruleset_for("inertia-page-missing-head"))._build_react_effective_context_from_facts(facts)

    assert "@inertiajs/react" in imports
    assert context.project_type == "inertia_spa"


def test_test_only_rule_scans_tests_ignored_by_production_inventory(tmp_path: Path) -> None:
    test_file = tmp_path / "tests" / "Feature" / "CreatesUserTest.php"
    test_file.parent.mkdir(parents=True)
    test_file.write_text(
        "<?php class CreatesUserTest extends TestCase { function test_it() { User::create([]); } }",
        encoding="utf-8",
    )
    facts = Facts(
        project_path=str(tmp_path),
        files=[],
        test_files=["tests/Feature/CreatesUserTest.php"],
    )
    engine = create_engine(
        ruleset=_ruleset_for("test-no-database-trait"),
        selected_rules=["test-no-database-trait"],
    )

    result = engine.run(facts, project_type="laravel_blade")

    assert [finding.rule_id for finding in result.findings] == [TestNoDatabaseTraitRule.id]
