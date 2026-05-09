from core.sarif import findings_to_sarif
from schemas.finding import Finding, Category, Severity


def test_findings_to_sarif_produces_valid_run_structure():
    finding = Finding(
        rule_id="no-closure-routes",
        title="Avoid closure routes",
        category=Category.ARCHITECTURE,
        severity=Severity.HIGH,
        file="routes/web.php",
        line_start=12,
        line_end=12,
        description="Detected closure route.",
        why_it_matters="Harder to test and organize.",
        suggested_fix="Use controller action.",
        confidence=0.8,
        tags=["laravel", "routes"],
    )

    sarif = findings_to_sarif([finding], tool_version="1.2.3")
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"]

    run = sarif["runs"][0]
    assert run["tool"]["driver"]["version"] == "1.2.3"
    assert run["tool"]["driver"]["rules"][0]["id"] == "no-closure-routes"

    result = run["results"][0]
    assert result["ruleId"] == "no-closure-routes"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "routes/web.php"
