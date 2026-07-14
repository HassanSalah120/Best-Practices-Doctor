from __future__ import annotations

from pathlib import Path

from analysis.facts_builder import FactsBuilder
from core.ruleset import RuleConfig
from rules.laravel.console_command_missing_tenant_scope import ConsoleCommandMissingTenantScopeRule
from rules.laravel.date_format_missing_cast import DateFormatMissingCastRule
from rules.laravel.env_usage import EnvOutsideConfigRule
from rules.laravel.missing_api_rate_limit_headers import MissingApiRateLimitHeadersRule
from rules.laravel.missing_cache_for_reference_data import MissingCacheForReferenceDataRule
from rules.laravel.missing_index_on_lookup_columns import MissingIndexOnLookupColumnsRule
from rules.laravel.model_cross_model_query import ModelCrossModelQueryRule
from rules.laravel.realtime_advisory import PublicAnonymousMutationAbuseReadinessRule
from rules.laravel.transaction_required_for_multi_write import TransactionRequiredForMultiWriteRule
from rules.php.circular_dependency import CircularDependencyRule
from rules.php.sql_injection_risk import SqlInjectionRiskRule
from rules.react.css_tailwind_best_practice_rules import TailwindArbitraryValueOveruseRule
from rules.react.no_array_index_key import NoArrayIndexKeyRule
from rules.react.postmessage_receiver_origin_not_verified import PostMessageReceiverOriginNotVerifiedRule
from rules.react.react_gap_expansion_rules import MissingEmptyStateRule
from schemas.facts import ClassInfo, EnvUsage, Facts, MethodInfo, QueryUsage, RouteInfo
from schemas.project_type import ProjectInfo


def _class(name: str) -> ClassInfo:
    return ClassInfo(
        name=name,
        fqcn=f"App\\Models\\{name}",
        file_path=f"domain/{name}.php",
        file_hash=name,
        line_start=1,
        line_end=40,
    )


def test_console_tenant_scope_requires_project_tenant_evidence() -> None:
    rule = ConsoleCommandMissingTenantScopeRule(RuleConfig())
    content = "class CleanupGames extends Command { function handle() { GameSession::where('state', 'old')->get(); } }"
    single_app = Facts(project_path=".")
    single_app.project_context.tenant_mode = "non_tenant"
    assert rule.analyze_regex("tools/CleanupGames.php", content, single_app) == []

    tenant_app = Facts(project_path=".")
    tenant_app.project_context.tenant_mode = "tenant"
    assert len(rule.analyze_regex("tools/CleanupGames.php", content, tenant_app)) == 1


def test_websocket_message_listener_is_not_window_postmessage() -> None:
    rule = PostMessageReceiverOriginNotVerifiedRule(RuleConfig())
    facts = Facts(project_path=".")
    socket = "socket.addEventListener('message', (event) => consume(event.data));"
    window = "window.addEventListener('message', (event) => consume(event.data));"
    assert rule.analyze_ast("client/realtime.ts", socket, facts) == []
    assert len(rule.analyze_ast("client/embed.ts", window, facts)) == 1


def test_numeric_case_sql_is_not_treated_as_string_taint(tmp_path: Path) -> None:
    source = """<?php
class BoardManagementService {
  public function updateBoardLayout(array $rows): void {
    foreach ($rows as $row) {
      $boardId = (int) $row['id'];
      $position = (int) $row['position'];
      $cases[] = "WHEN id = {$boardId} THEN {$position}";
    }
    $caseSql = 'CASE ' . implode(' ', $cases) . ' END';
    DB::raw($caseSql);
  }
}
"""
    path = tmp_path / "domain" / "BoardManagementService.php"
    path.parent.mkdir(parents=True)
    path.write_text(source, encoding="utf-8")
    method = MethodInfo(
        name="updateBoardLayout",
        class_name="BoardManagementService",
        file_path="domain/BoardManagementService.php",
        file_hash="board",
        line_start=3,
        line_end=11,
        call_sites=["DB::raw($caseSql)"],
    )
    assert SqlInjectionRiskRule(RuleConfig()).analyze(Facts(project_path=str(tmp_path), methods=[method])) == []


def test_fresh_clock_format_is_not_a_model_cast_problem() -> None:
    rule = DateFormatMissingCastRule(RuleConfig())
    facts = Facts(project_path=".")
    assert rule.analyze_regex("domain/SeriesNamer.php", "now()->format('Y-m-d H:i')", facts) == []
    assert len(
        rule.analyze_regex(
            "domain/Order.php",
            "Carbon::createFromFormat('Y-m-d', $order->ordered_at)->format('Y-m-d')",
            facts,
        ),
    ) >= 1


def test_outer_transaction_covers_unique_internal_multiwrite_method() -> None:
    cleanup = MethodInfo(
        name="deleteGameData",
        class_name="SessionLifecycleService",
        file_path="domain/SessionLifecycleService.php",
        file_hash="service",
        call_sites=["GameAction::query()->delete()", "GamePlayer::query()->delete()"],
    )
    reset = MethodInfo(
        name="hardReset",
        class_name="SessionLifecycleService",
        file_path="domain/SessionLifecycleService.php",
        file_hash="service",
        call_sites=["DB::transaction(fn () => $this->deleteGameData())", "$this->deleteGameData()"],
    )
    facts = Facts(
        project_path=".",
        methods=[cleanup, reset],
        queries=[
            QueryUsage(file_path=cleanup.file_path, line_number=8, method_name=cleanup.name, model="GameAction", method_chain="query->delete", query_type="delete"),
            QueryUsage(file_path=cleanup.file_path, line_number=9, method_name=cleanup.name, model="GamePlayer", method_chain="query->delete", query_type="delete"),
        ],
    )
    assert TransactionRequiredForMultiWriteRule(RuleConfig()).analyze(facts) == []


def test_self_queries_and_all_model_navigation_graphs_are_not_boundary_cycles() -> None:
    session = _class("GameSession")
    player = _class("GameSessionPlayer")
    facts = Facts(project_path=".", classes=[session, player], models=[session, player])
    facts.methods = [
        MethodInfo(name="resolveMeta", class_name=session.name, class_fqcn=session.fqcn, file_path=session.file_path, file_hash="s", call_sites=["GameSessionPlayer::query()->first()"]),
        MethodInfo(name="session", class_name=player.name, class_fqcn=player.fqcn, file_path=player.file_path, file_hash="p", call_sites=["GameSession::query()->first()"]),
    ]
    facts.queries = [
        QueryUsage(file_path=session.file_path, line_number=12, method_name="resolveMeta", model="self", method_chain="query->leftJoin->first"),
    ]
    assert ModelCrossModelQueryRule(RuleConfig()).analyze(facts) == []
    assert CircularDependencyRule(RuleConfig()).analyze(facts) == []


def test_live_domain_model_name_is_not_reference_data_by_substring() -> None:
    facts = Facts(project_path=".")
    facts.methods = [MethodInfo(name="other", class_name="CacheUser", file_path="domain/CacheUser.php", file_hash="c", call_sites=["Cache::remember('x', 60, fn () => 1)"])]
    facts.queries = [
        QueryUsage(file_path="domain/GameStatusEvent.php", line_number=8, method_name="getCurrent", model="GameStatusEvent", method_chain="where->first"),
        QueryUsage(file_path="domain/CategoryAnswer.php", line_number=9, method_name="getReveal", model="CategoryAnswer", method_chain="where->get"),
    ]
    assert MissingCacheForReferenceDataRule(RuleConfig()).analyze(facts) == []


def test_trusted_proxy_bootstrap_env_is_framework_wiring() -> None:
    facts = Facts(
        project_path=".",
        env_usages=[EnvUsage(file_path="foundation/start.php", line_number=20, snippet="$middleware->trustProxies(at: env('TRUSTED_PROXIES'));" )],
    )
    assert EnvOutsideConfigRule(RuleConfig()).analyze(facts) == []


def test_throttle_headers_are_framework_default_unless_explicitly_removed(tmp_path: Path) -> None:
    route = RouteInfo(method="GET", uri="api/items", middleware=["api", "throttle:api"], file_path="http/routes.php")
    facts = Facts(project_path=str(tmp_path), routes=[route])
    assert MissingApiRateLimitHeadersRule(RuleConfig()).analyze(facts) == []

    middleware = tmp_path / "http" / "StripHeaders.php"
    middleware.parent.mkdir(parents=True)
    middleware.write_text("<?php $response->headers->remove('Retry-After');", encoding="utf-8")
    facts.files = ["http/StripHeaders.php"]
    assert len(MissingApiRateLimitHeadersRule(RuleConfig()).analyze(facts)) == 1


def test_primary_column_is_extracted_as_an_index(tmp_path: Path) -> None:
    migration = tmp_path / "db" / "create_password_resets.php"
    migration.parent.mkdir(parents=True)
    migration.write_text(
        """<?php
use Illuminate\\Database\\Migrations\\Migration;
return new class extends Migration {
 public function up(): void { Schema::create('password_reset_tokens', function ($table) {
   $table->string('email')->primary();
 }); }
};
""",
        encoding="utf-8",
    )
    facts = FactsBuilder(ProjectInfo(root_path=str(tmp_path), type="laravel")).build()
    assert any(index.kind == "primary" and index.columns == ["email"] for index in facts.migration_indexes)
    assert MissingIndexOnLookupColumnsRule(RuleConfig()).analyze(facts) == []


def test_named_limiter_discovery_is_not_provider_path_dependent(tmp_path: Path) -> None:
    route_file = tmp_path / "modules" / "game_routes.php"
    limiter_file = tmp_path / "foundation" / "TrafficPolicy.php"
    route_file.parent.mkdir(parents=True)
    limiter_file.parent.mkdir(parents=True)
    route_file.write_text(
        "Route::middleware(['throttle:ws-command'])->group(function () {\nRoute::post('/api/ws/command', Handler::class);\n});",
        encoding="utf-8",
    )
    limiter_file.write_text("RateLimiter::for('ws-command', fn () => Limit::perMinute(30));", encoding="utf-8")
    route = RouteInfo(
        method="POST",
        uri="api/ws/command",
        controller="RealtimeCommandController",
        middleware=["internal-key"],
        file_path="modules/game_routes.php",
        line_number=2,
    )
    facts = Facts(
        project_path=str(tmp_path),
        files=["modules/game_routes.php", "foundation/TrafficPolicy.php"],
        routes=[route],
    )
    assert PublicAnonymousMutationAbuseReadinessRule(RuleConfig()).analyze(facts) == []


def test_explicit_leaderboard_empty_state_is_recognized() -> None:
    source = """export default function AdminLeaderboardPage({ leaderboard }) {
 return <main>{leaderboard.length > 0 ? leaderboard.map(row => <div key={row.id}>{row.name}</div>) : <p>No scores yet</p>}</main>;
}"""
    assert MissingEmptyStateRule(RuleConfig()).analyze_ast("ui/pages/AdminLeaderboardPage.tsx", source, Facts(project_path=".")) == []


def test_brand_arbitrary_values_and_fixed_skeleton_positions_are_allowed() -> None:
    facts = Facts(project_path=".", npm_packages={"tailwindcss": "^4"})
    branded = '<div className="bg-[#180d2b] from-[#ff2a8a] via-[#7b2cff] to-[#1ee3cf] tracking-[0.08em]" />'
    skeleton = "Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} />)"
    assert TailwindArbitraryValueOveruseRule(RuleConfig()).analyze_regex("ui/LmsLayout.tsx", branded, facts) == []
    assert NoArrayIndexKeyRule(RuleConfig()).analyze_regex("ui/BoardSkeleton.tsx", skeleton, facts) == []
