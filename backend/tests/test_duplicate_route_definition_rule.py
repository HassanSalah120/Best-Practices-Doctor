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

