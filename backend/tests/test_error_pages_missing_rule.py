from __future__ import annotations

from core.ruleset import RuleConfig
from rules.laravel.error_pages_missing import ErrorPagesMissingRule
from schemas.facts import Facts


def test_error_pages_missing_valid_near_invalid():
    rule = ErrorPagesMissingRule(RuleConfig())

    valid = Facts(project_path=".")
    valid.files = [
        "resources/views/errors/404.blade.php",
        "resources/views/errors/500.blade.php",
        "resources/views/errors/403.blade.php",
        "resources/views/errors/419.blade.php",
        "resources/views/errors/429.blade.php",
        "resources/views/errors/503.blade.php",
    ]
    assert rule.run(valid).findings == []

    near = Facts(project_path=".")
    near.project_context.project_type = "api_backend"
    near.files = ["routes/api.php", "app/Http/Controllers/Api/UserController.php"]
    assert rule.run(near).findings == []

    invalid = Facts(project_path=".")
    invalid.files = ["resources/views/welcome.blade.php", "routes/web.php"]
    findings = rule.run(invalid).findings
    assert findings
    assert findings[0].rule_id == "error-pages-missing"
    assert findings[0].severity.value in {"medium", "high"}


def test_error_pages_missing_recommended_only_low_severity():
    rule = ErrorPagesMissingRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.files = [
        "resources/views/errors/404.blade.php",
        "resources/views/errors/500.blade.php",
    ]

    findings = rule.run(facts).findings
    assert findings
    assert findings[0].rule_id == "error-pages-missing"
    assert findings[0].severity.value == "low"


def test_error_pages_missing_accepts_inertia_error_pages_without_blade():
    rule = ErrorPagesMissingRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.files = [
        "app/Http/Middleware/HandleInertiaRequests.php",
        "resources/js/Pages/Errors/404.tsx",
        "resources/js/Pages/Errors/500.tsx",
    ]

    findings = rule.run(facts).findings
    assert findings == []


def test_error_pages_missing_flags_inertia_when_core_pages_missing():
    rule = ErrorPagesMissingRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.files = [
        "app/Http/Middleware/HandleInertiaRequests.php",
        "resources/js/Pages/Errors/404.tsx",
    ]

    findings = rule.run(facts).findings
    assert findings
    assert findings[0].rule_id == "error-pages-missing"
    assert findings[0].severity.value in {"medium", "high"}


def test_error_pages_missing_accepts_prefixed_inertia_error_pages():
    rule = ErrorPagesMissingRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.files = [
        "app/Http/Middleware/HandleInertiaRequests.php",
        "resources/js/Pages/Errors/Error404.tsx",
        "resources/js/Pages/Errors/Error500.tsx",
    ]

    findings = rule.run(facts).findings
    assert findings == []
