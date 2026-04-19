from core.ruleset import RuleConfig
from schemas.facts import Facts, RouteInfo
from rules.laravel.duplicate_route_definition import DuplicateRouteDefinitionRule


def test_duplicate_route_definition_finds_same_method_and_uri():
    facts = Facts(project_path="x")
    facts.routes = [
        RouteInfo(method="GET", uri="/patients", file_path="routes/web.php", line_number=10),
        RouteInfo(method="GET", uri="/patients", file_path="routes/api.php", line_number=33),
    ]

    rule = DuplicateRouteDefinitionRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings

    assert len(findings) == 1
    assert findings[0].rule_id == "duplicate-route-definition"


def test_duplicate_route_definition_ignores_different_methods():
    facts = Facts(project_path="x")
    facts.routes = [
        RouteInfo(method="GET", uri="/patients", file_path="routes/web.php", line_number=10),
        RouteInfo(method="POST", uri="/patients", file_path="routes/web.php", line_number=20),
    ]

    rule = DuplicateRouteDefinitionRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings

    assert findings == []


def test_duplicate_route_definition_prefers_artisan_source_of_truth():
    facts = Facts(project_path="x")
    facts.routes = [
        RouteInfo(
            method="POST",
            uri="/transferhistorie/admin/players",
            file_path="routes/web.php",
            line_number=11,
            source="static",
        ),
        RouteInfo(
            method="POST",
            uri="/transferhistorie/admin/players",
            file_path="routes/cache.php",
            line_number=200,
            source="static",
        ),
        RouteInfo(
            method="POST",
            uri="/transferhistorie/admin/players",
            file_path="routes/web.php",
            line_number=11,
            source="artisan",
        ),
    ]

    rule = DuplicateRouteDefinitionRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings

    assert findings == []


def test_duplicate_route_definition_reports_when_artisan_confirms_duplicate():
    facts = Facts(project_path="x")
    facts.routes = [
        RouteInfo(
            method="POST",
            uri="/patients",
            file_path="routes/web.php",
            line_number=10,
            source="artisan",
        ),
        RouteInfo(
            method="POST",
            uri="/patients",
            file_path="routes/web.php",
            line_number=25,
            source="artisan",
        ),
    ]

    rule = DuplicateRouteDefinitionRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings

    assert len(findings) == 1
