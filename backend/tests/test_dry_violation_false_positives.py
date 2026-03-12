from core.ruleset import RuleConfig
from rules.php.dry_violation import DryViolationRule
from schemas.facts import Facts, DuplicateBlock


def test_dry_violation_collapses_repeated_hash_blocks():
    facts = Facts(project_path=".")
    facts.duplicates.extend(
        [
            DuplicateBlock(
                hash="dup-hash",
                token_count=120,
                occurrences=[("app/Foo.php", 10, 20), ("app/Bar.php", 30, 40)],
                code_snippet="if ($x) { return 1; }",
            ),
            DuplicateBlock(
                hash="dup-hash",
                token_count=130,
                occurrences=[("app/Foo.php", 18, 28), ("app/Baz.php", 50, 62)],
                code_snippet="if ($x) { return 1; }",
            ),
        ]
    )

    rule = DryViolationRule(RuleConfig())
    res = rule.run(facts, project_type="laravel_api")

    assert len(res.findings) == 1
    assert "duplicated in 3 places" in res.findings[0].description
    assert {res.findings[0].file, *set(res.findings[0].related_files)} == {
        "app/Foo.php",
        "app/Bar.php",
        "app/Baz.php",
    }


def test_dry_violation_ignores_route_registrar_boilerplate_by_default():
    facts = Facts(project_path=".")
    facts.duplicates.append(
        DuplicateBlock(
            hash="route-hash",
            token_count=180,
            occurrences=[
                ("app/Http/RouteRegistrars/Admin/A.php", 10, 35),
                ("app/Http/RouteRegistrars/Admin/B.php", 12, 37),
            ],
            code_snippet="Route::middleware(['auth'])->prefix('admin')->group(function () {});",
        )
    )

    rule = DryViolationRule(RuleConfig())
    res = rule.run(facts, project_type="laravel_api")

    assert not res.findings


def test_dry_violation_ignores_provider_binding_boilerplate_by_default():
    facts = Facts(project_path=".")
    facts.duplicates.append(
        DuplicateBlock(
            hash="provider-hash",
            token_count=180,
            occurrences=[("app/Providers/A.php", 10, 30), ("app/Providers/B.php", 12, 32)],
            code_snippet="$this->app->bind(Foo::class, FooImpl::class);",
        )
    )

    rule = DryViolationRule(RuleConfig())
    res = rule.run(facts, project_type="laravel_api")
    assert not res.findings


def test_dry_violation_filters_short_span_blocks_unless_token_count_is_large():
    facts = Facts(project_path=".")
    facts.duplicates.append(
        DuplicateBlock(
            hash="short-hash",
            token_count=75,
            occurrences=[("app/Services/A.php", 10, 12), ("app/Services/B.php", 20, 22)],
            code_snippet="$value = trim($value);",
        )
    )

    rule = DryViolationRule(RuleConfig())
    res = rule.run(facts, project_type="laravel_api")
    assert not res.findings

    rule2 = DryViolationRule(RuleConfig(thresholds={"min_tokens_for_short_span": 70}))
    res2 = rule2.run(facts, project_type="laravel_api")
    assert len(res2.findings) == 1


def test_dry_violation_ignores_same_file_only_duplicates_by_default():
    facts = Facts(project_path=".")
    facts.duplicates.append(
        DuplicateBlock(
            hash="same-file",
            token_count=180,
            occurrences=[("app/Services/A.php", 10, 30), ("app/Services/A.php", 40, 60)],
            code_snippet="if ($a && $b) { $sum += 1; }",
        )
    )

    rule = DryViolationRule(RuleConfig())
    res = rule.run(facts, project_type="laravel_api")
    assert not res.findings

    rule2 = DryViolationRule(RuleConfig(thresholds={"min_unique_files": 1}))
    res2 = rule2.run(facts, project_type="laravel_api")
    assert len(res2.findings) == 1
