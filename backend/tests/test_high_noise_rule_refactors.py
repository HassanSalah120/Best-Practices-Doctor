from __future__ import annotations

from pathlib import Path

from analysis.facts_builder import FactsBuilder
from core.detector import ProjectDetector
from core.ruleset import RuleConfig
from rules.laravel.dto_suggestion import DtoSuggestionRule
from rules.laravel.eloquent_raw_where_string import EloquentRawWhereStringRule
from rules.laravel.missing_csrf_token_verification import MissingCsrfTokenVerificationRule
from schemas.facts import AssocArrayLiteral, Facts, ProjectContext, RouteInfo


def _dto_context() -> ProjectContext:
    expectation = {
        "dto_data_objects_preferred": {
            "enabled": True,
            "confidence": 0.88,
            "evidence": ["data_object=App\\Contracts\\CreateOrderData"],
        },
    }
    return ProjectContext(
        team_expectations=expectation,
        backend_team_expectations=expectation,
    )


def _large_array(**overrides) -> AssocArrayLiteral:
    values = {
        "file_path": "src/Workflows/CreateOrder.php",
        "line_number": 20,
        "method_name": "execute",
        "class_fqcn": "Domain\\Orders\\CreateOrder",
        "key_count": 10,
        "used_as": "assignment",
        "target": "$payload",
        "consumer_calls": ["$this->orders->handle"],
    }
    values.update(overrides)
    return AssocArrayLiteral(**values)


def test_eloquent_where_requires_a_dynamic_explicit_raw_expression() -> None:
    rule = EloquentRawWhereStringRule()
    facts = Facts(project_path=".")

    genuine = "<?php User::query()->where(DB::raw($request->input('predicate')))->get();"
    assigned = "<?php $expr = DB::raw($column); User::query()->where($expr)->get();"
    qualified = "<?php User::query()->where(\\Illuminate\\Support\\Facades\\DB::raw($predicate))->get();"
    assert len(rule.analyze_regex("src/UserLookup.php", genuine, facts)) == 1
    assert len(rule.analyze_regex("src/UserLookup.php", assigned, facts)) == 1
    assert len(rule.analyze_regex("src/UserLookup.php", qualified, facts)) == 1

    safe_or_unrelated = [
        "<?php User::query()->where('profiles.status', $status)->get();",
        "<?php User::query()->where('meta->status', $status)->get();",
        "<?php User::query()->where('status = ' . $status)->get();",
        "<?php User::query()->where(DB::raw('LOWER(email)'))->get();",
        "<?php // User::where(DB::raw($request->input('predicate')));",
        "<?php $example = \"User::where(DB::raw(\\$predicate))\";",
    ]
    for content in safe_or_unrelated:
        assert rule.analyze_regex("src/UserLookup.php", content, facts) == []


def test_dto_suggestion_requires_both_convention_and_a_real_boundary() -> None:
    rule = DtoSuggestionRule(RuleConfig(thresholds={"min_keys": 10}))

    positive = Facts(project_path=".", project_context=_dto_context(), assoc_arrays=[_large_array()])
    assert len(rule.analyze(positive)) == 1

    no_convention = Facts(project_path=".", assoc_arrays=[_large_array()])
    assert rule.analyze(no_convention) == []

    local_only = Facts(
        project_path=".",
        project_context=_dto_context(),
        assoc_arrays=[_large_array(consumer_calls=["$this->normalize"])],
    )
    assert rule.analyze(local_only) == []

    persistence_payload = Facts(
        project_path=".",
        project_context=_dto_context(),
        assoc_arrays=[_large_array(consumer_calls=["$order->update"])],
    )
    assert rule.analyze(persistence_payload) == []

    inside_data_object = Facts(
        project_path=".",
        project_context=_dto_context(),
        assoc_arrays=[_large_array(class_fqcn="Domain\\Orders\\CreateOrderPayload")],
    )
    assert rule.analyze(inside_data_object) == []


def test_dto_evidence_is_extracted_without_relying_on_a_dto_folder(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text(
        '{"require":{"php":"^8.2","laravel/framework":"^12.0"}}',
        encoding="utf-8",
    )
    data_object = tmp_path / "src" / "Contracts" / "CreateOrderData.php"
    data_object.parent.mkdir(parents=True)
    data_object.write_text(
        "<?php namespace App\\Contracts; final class CreateOrderData {}",
        encoding="utf-8",
    )
    action = tmp_path / "src" / "Workflows" / "CreateOrder.php"
    action.parent.mkdir(parents=True)
    action.write_text(
        """<?php
namespace App\\Workflows;
final class CreateOrder {
    public function execute(): void {
        $payload = [
            'customer_id' => 1, 'currency' => 'USD', 'subtotal' => 10,
            'tax' => 1, 'shipping' => 2, 'discount' => 0,
            'total' => 13, 'notes' => null, 'source' => 'web',
            'locale' => 'en',
        ];
        $this->orders->handle($payload);
    }
}
""",
        encoding="utf-8",
    )

    info = ProjectDetector(str(tmp_path)).detect()
    facts = FactsBuilder(info).build()
    matching = [item for item in facts.assoc_arrays if item.file_path.endswith("CreateOrder.php")]
    assert matching and matching[0].consumer_calls == ["$this->orders->handle"]
    assert facts.project_context.backend_team_expectations["dto_data_objects_preferred"]["enabled"] is True
    assert len(DtoSuggestionRule(RuleConfig()).analyze(facts)) == 1


def test_csrf_rule_requires_session_evidence_and_exact_api_semantics() -> None:
    rule = MissingCsrfTokenVerificationRule(RuleConfig())

    browser_route = RouteInfo(
        method="POST",
        uri="/apiary/colonies",
        action="ColonyController@store",
        file_path="routes/capitals.php",
        line_number=8,
        middleware=["auth"],
    )
    assert len(rule.analyze(Facts(project_path=".", routes=[browser_route]))) == 1

    unknown_route = browser_route.model_copy(update={"middleware": []})
    assert rule.analyze(Facts(project_path=".", routes=[unknown_route])) == []

    token_route = browser_route.model_copy(update={"middleware": ["auth:sanctum"]})
    assert rule.analyze(Facts(project_path=".", routes=[token_route])) == []

    auth_web_only = browser_route.model_copy(update={"middleware": ["auth:web"]})
    assert len(rule.analyze(Facts(project_path=".", routes=[auth_web_only]))) == 1

    custom_api_prefix = browser_route.model_copy(update={"middleware": ["auth", "apiary"]})
    assert len(rule.analyze(Facts(project_path=".", routes=[custom_api_prefix]))) == 1


def test_csrf_rule_resolves_custom_web_registration_and_explicit_exemption(tmp_path: Path) -> None:
    rule = MissingCsrfTokenVerificationRule(RuleConfig())
    routes = tmp_path / "endpoints"
    routes.mkdir(parents=True)
    (routes / "browser-actions.php").write_text("<?php", encoding="utf-8")
    bootstrap = tmp_path / "bootstrap"
    bootstrap.mkdir()
    (bootstrap / "app.php").write_text(
        """<?php
Application::configure()->withRouting(
    web: base_path('endpoints/browser-actions.php'),
)->withMiddleware(function ($middleware) {
    $middleware->validateCsrfTokens(except: ['callbacks/trusted']);
});
""",
        encoding="utf-8",
    )
    base = {
        "method": "POST",
        "action": "BrowserActionController@store",
        "file_path": "endpoints/browser-actions.php",
        "line_number": 5,
        "middleware": ["auth"],
    }
    protected = RouteInfo(uri="profile/save", **base)
    exempt = RouteInfo(uri="callbacks/trusted", **base)
    facts = Facts(
        project_path=str(tmp_path),
        files=["bootstrap/app.php", "endpoints/browser-actions.php"],
        routes=[protected, exempt],
    )

    # Both routes are understood: one through the configured web stack, the
    # other through a deliberately configured exact exemption.
    assert rule.analyze(facts) == []


def test_facts_builder_enriches_custom_web_and_csrf_group_routes(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text(
        '{"require":{"laravel/framework":"^12.0"}}',
        encoding="utf-8",
    )
    bootstrap = tmp_path / "bootstrap" / "app.php"
    bootstrap.parent.mkdir(parents=True)
    bootstrap.write_text(
        """<?php
Application::configure()->withRouting(
    web: base_path('endpoints/browser.php'),
)->withMiddleware(function ($middleware) {
    $middleware->group('browser-secure', [
        App\\Http\\Middleware\\VerifyCsrfToken::class,
    ]);
});
""",
        encoding="utf-8",
    )
    route_file = tmp_path / "endpoints" / "browser.php"
    route_file.parent.mkdir()
    route_file.write_text(
        "<?php Route::middleware(['browser-secure', 'auth'])->post('/profile', fn () => null);",
        encoding="utf-8",
    )

    facts = FactsBuilder(ProjectDetector(str(tmp_path)).detect()).build()

    assert len(facts.routes) == 1
    middleware = {item.lower() for item in facts.routes[0].middleware}
    assert {"web", "browser-secure", "auth", "verifycsrftoken"}.issubset(middleware)
    assert MissingCsrfTokenVerificationRule(RuleConfig()).analyze(facts) == []
