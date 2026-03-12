from __future__ import annotations

from pathlib import Path

from analysis.facts_builder import FactsBuilder
from core.ruleset import RuleConfig
from rules.laravel.missing_auth_on_mutating_api_routes import MissingAuthOnMutatingApiRoutesRule
from rules.laravel.policy_coverage_on_mutations import PolicyCoverageOnMutationsRule
from schemas.facts import ClassInfo, MethodInfo, QueryUsage
from schemas.project_type import ProjectInfo, ProjectType


def _build_facts(project: Path):
    info = ProjectInfo(root_path=str(project), project_type=ProjectType.LARAVEL_API)
    builder = FactsBuilder(project_info=info)
    return builder.build()


def test_phase3_route_context_inherits_nested_group_prefix_and_middleware(tmp_path: Path):
    routes_dir = tmp_path / "routes"
    routes_dir.mkdir(parents=True, exist_ok=True)
    (routes_dir / "api.php").write_text(
        """<?php
Route::middleware('auth:sanctum')->prefix('clinic')->group(function () {
    Route::middleware(['verified', 'throttle:api'])->prefix('v1')->group(function () {
        Route::post('/patients', [PatientController::class, 'store'])->name('patients.store');
    });
});
""",
        encoding="utf-8",
    )

    facts = _build_facts(tmp_path)
    routes = [r for r in facts.routes if r.action == "store"]
    assert len(routes) == 1
    route = routes[0]
    assert route.method == "POST"
    assert route.uri == "/clinic/v1/patients"
    assert route.controller == "PatientController"
    assert route.action == "store"
    assert route.name == "patients.store"
    assert "auth:sanctum" in route.middleware
    assert "verified" in route.middleware
    assert "throttle:api" in route.middleware


def test_phase3_route_context_supports_legacy_group_array_style(tmp_path: Path):
    routes_dir = tmp_path / "routes"
    routes_dir.mkdir(parents=True, exist_ok=True)
    (routes_dir / "api.php").write_text(
        """<?php
Route::group(['middleware' => ['auth:sanctum', 'can:update,patient'], 'prefix' => 'admin'], function () {
    Route::delete('patients/{id}', 'PatientController@destroy');
});
""",
        encoding="utf-8",
    )

    facts = _build_facts(tmp_path)
    routes = [r for r in facts.routes if r.action == "destroy"]
    assert len(routes) == 1
    route = routes[0]
    assert route.method == "DELETE"
    assert route.uri == "/admin/patients/{id}"
    assert route.controller == "PatientController"
    assert "auth:sanctum" in route.middleware
    assert "can:update,patient" in route.middleware


def test_phase3_missing_auth_rule_uses_enriched_route_context(tmp_path: Path):
    routes_dir = tmp_path / "routes"
    routes_dir.mkdir(parents=True, exist_ok=True)
    (routes_dir / "api.php").write_text(
        """<?php
Route::middleware('auth:sanctum')->prefix('clinic')->group(function () {
    Route::post('/patients', [PatientController::class, 'store']);
});
Route::post('/public-mutating', [PublicController::class, 'store']);
""",
        encoding="utf-8",
    )

    facts = _build_facts(tmp_path)
    rule = MissingAuthOnMutatingApiRoutesRule(RuleConfig())
    findings = rule.analyze_regex("routes/api.php", "", facts)

    assert len(findings) == 1
    assert findings[0].context.lower().startswith("post /public-mutating")


def test_phase3_policy_rule_respects_group_middleware_context(tmp_path: Path):
    routes_dir = tmp_path / "routes"
    routes_dir.mkdir(parents=True, exist_ok=True)
    (routes_dir / "api.php").write_text(
        """<?php
Route::middleware('auth:sanctum')->group(function () {
    Route::post('/patients', [PatientController::class, 'store']);
});
""",
        encoding="utf-8",
    )

    facts = _build_facts(tmp_path)
    facts.controllers.append(
        ClassInfo(
            name="PatientController",
            fqcn="App\\Http\\Controllers\\PatientController",
            file_path="app/Http/Controllers/PatientController.php",
            file_hash="deadbeef",
            line_start=1,
            line_end=100,
        )
    )
    facts.methods.append(
        MethodInfo(
            name="store",
            class_name="PatientController",
            class_fqcn="App\\Http\\Controllers\\PatientController",
            file_path="app/Http/Controllers/PatientController.php",
            file_hash="deadbeef",
            line_start=10,
            line_end=80,
            loc=71,
            call_sites=[],
        )
    )
    facts.queries.append(
        QueryUsage(
            file_path="app/Http/Controllers/PatientController.php",
            line_number=20,
            method_name="store",
            model="Patient",
            method_chain="create",
        )
    )

    findings = PolicyCoverageOnMutationsRule(RuleConfig()).run(facts, project_type="laravel_api").findings
    assert findings == []

