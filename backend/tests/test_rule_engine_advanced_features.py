from pathlib import Path

from core.rule_engine import ALL_RULES, RuleEngine
from core.ruleset import RuleConfig, Ruleset
from schemas.facts import Facts, MethodInfo


def _ruleset_with_only(rule_id: str, config: RuleConfig | None = None) -> Ruleset:
    rules = {rid: RuleConfig(enabled=False) for rid in ALL_RULES.keys()}
    rules[rule_id] = config or RuleConfig(enabled=True)
    return Ruleset(rules=rules, name="balanced")


def test_explicit_ruleset_disables_unspecified_rules():
    ruleset = Ruleset(rules={"no-log-debug-in-app": RuleConfig(enabled=True)}, name="balanced")

    assert ruleset.get_rule_config("no-log-debug-in-app").enabled is True
    assert ruleset.get_rule_config("fat-controller").enabled is False


def test_rule_engine_confidence_floor_filters_low_confidence_regex_findings(tmp_path: Path):
    root = tmp_path / "proj"
    routes = root / "routes"
    routes.mkdir(parents=True, exist_ok=True)
    (routes / "web.php").write_text("<?php\nRoute::get('/x', function () { return 'ok'; });\n", encoding="utf-8")

    facts = Facts(project_path=str(root))
    facts.files = ["routes/web.php"]

    rs = _ruleset_with_only(
        "no-closure-routes",
        RuleConfig(enabled=True, thresholds={"min_confidence": 0.8}),
    )
    engine = RuleEngine(rs)
    res = engine.run(facts, project_type="laravel_api")

    assert res.findings == []
    assert res.filtered_by_confidence >= 1


def test_rule_engine_startup_profile_filters_low_confidence_ast_advisory():
    facts = Facts(project_path=".")
    facts.methods.append(
        MethodInfo(
            name="run",
            class_name="BillingService",
            class_fqcn="App\\Services\\BillingService",
            file_path="app/Services/BillingService.php",
            file_hash="deadbeef",
            line_start=10,
            line_end=16,
            loc=7,
            throws=["Exception"],
        )
    )

    rs = _ruleset_with_only(
        "custom-exception-suggestion",
        RuleConfig(enabled=True, thresholds={"min_confidence": 0.75}),
    )
    rs.name = "startup"
    engine = RuleEngine(rs)
    res = engine.run(facts, project_type="laravel_api")

    assert res.findings == []
    assert res.filtered_by_confidence >= 1


def test_rule_engine_applies_bpd_ignore_with_expiry(tmp_path: Path):
    root = tmp_path / "proj"
    routes = root / "routes"
    routes.mkdir(parents=True, exist_ok=True)
    (routes / "web.php").write_text(
        "<?php\n// @bpd-ignore-next-line no-closure-routes temp-fix until:2099-12-31\n"
        "Route::get('/x', function () { return 'ok'; });\n",
        encoding="utf-8",
    )
    facts = Facts(project_path=str(root))
    facts.files = ["routes/web.php"]

    engine = RuleEngine(_ruleset_with_only("no-closure-routes"))
    res = engine.run(facts, project_type="laravel_api")
    assert res.findings == []
    assert res.suppressed_count >= 1

    # Expired suppression should no longer suppress.
    (routes / "web.php").write_text(
        "<?php\n// @bpd-ignore-next-line no-closure-routes temp-fix until:2000-01-01\n"
        "Route::get('/x', function () { return 'ok'; });\n",
        encoding="utf-8",
    )
    res2 = engine.run(facts, project_type="laravel_api")
    assert len(res2.findings) == 1


def test_rule_engine_differential_mode_filters_to_changed_files(tmp_path: Path):
    root = tmp_path / "proj"
    svc = root / "app" / "Services"
    svc.mkdir(parents=True, exist_ok=True)
    (svc / "A.php").write_text("<?php\nLog::debug('A');\n", encoding="utf-8")
    (svc / "B.php").write_text("<?php\nLog::debug('B');\n", encoding="utf-8")

    facts = Facts(project_path=str(root))
    facts.files = ["app/Services/A.php", "app/Services/B.php"]

    engine = RuleEngine(_ruleset_with_only("no-log-debug-in-app"))
    res = engine.run(
        facts,
        project_type="laravel_api",
        differential_mode=True,
        changed_files={"app/Services/A.php"},
    )

    assert len(res.findings) == 1
    assert res.findings[0].file == "app/Services/A.php"
    assert res.differential_filtered >= 1
