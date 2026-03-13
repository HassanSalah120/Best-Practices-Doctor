from schemas.facts import Facts, StringLiteral, ClassInfo
from core.ruleset import RuleConfig
from rules.laravel.enum_suggestion import EnumSuggestionRule


def test_enum_suggestion_is_conservative_for_infra_tokens():
    # "redis"/"memcached" are common cache/store driver strings and should not trigger
    # enum suggestions by default heuristics.
    facts = Facts(project_path="x")
    facts.string_literals = [
        StringLiteral(value="redis", occurrences=[("a.php", 1), ("b.php", 2), ("c.php", 3)]),
        StringLiteral(value="memcached", occurrences=[("a.php", 5), ("b.php", 6), ("c.php", 7)]),
    ]

    rule = EnumSuggestionRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings
    assert all(f.rule_id != "enum-suggestion" for f in findings)


def test_string_literal_collection_skips_array_keys():
    # Guardrail: the facts builder should not treat array keys as enum candidates.
    from analysis.facts_builder import FactsBuilder
    from core.detector import ProjectDetector
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "app" / "Http" / "Controllers").mkdir(parents=True)
        p = root / "app" / "Http" / "Controllers" / "K.php"
        p.write_text(
            "<?php\n"
            "namespace App\\Http\\Controllers;\n"
            "class K { public function x() { $a = ['host' => 'redis']; $b = ['port' => '6379']; } }\n",
            encoding="utf-8",
        )

        info = ProjectDetector(str(root)).detect()
        facts = FactsBuilder(info).build()

        vals = {s.value for s in facts.string_literals}
        assert "host" not in vals
        assert "port" not in vals


def test_enum_suggestion_fires_for_explicit_status_context_cluster():
    facts = Facts(project_path="x")
    facts.string_literals = [
        StringLiteral(value="pending", occurrences=[("a.php", 10, "status"), ("b.php", 20, "status")]),
        StringLiteral(value="completed", occurrences=[("a.php", 30, "status"), ("b.php", 40, "status")]),
    ]

    rule = EnumSuggestionRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings
    assert any(f.rule_id == "enum-suggestion" for f in findings)
    assert any((f.metadata or {}).get("context") == "status" for f in findings)


def test_enum_suggestion_ignores_single_repeated_status_without_context():
    facts = Facts(project_path="x")
    facts.string_literals = [
        StringLiteral(value="scheduled", occurrences=[("a.php", 10), ("b.php", 20), ("c.php", 30)]),
    ]

    rule = EnumSuggestionRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings
    assert all(f.rule_id != "enum-suggestion" for f in findings)


def test_enum_suggestion_ignores_lang_dictionary_occurrences():
    facts = Facts(project_path="x")
    facts.string_literals = [
        StringLiteral(
            value="pending",
            occurrences=[
                ("resources/lang/en/ui.php", 10),
                ("resources/lang/en/ui.php", 30),
                ("resources/lang/ar/ui.php", 12),
                ("resources/lang/ar/ui.php", 25),
            ],
        ),
    ]

    rule = EnumSuggestionRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings
    assert all(f.rule_id != "enum-suggestion" for f in findings)


def test_enum_suggestion_counts_only_non_lang_occurrences():
    facts = Facts(project_path="x")
    facts.string_literals = [
        StringLiteral(
            value="pending",
            occurrences=[
                ("resources/lang/en/ui.php", 10),
                ("app/Services/A.php", 11),
                ("app/Services/B.php", 22),
                ("app/Services/C.php", 33),
            ],
        ),
    ]

    rule = EnumSuggestionRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings
    assert all(f.rule_id != "enum-suggestion" for f in findings)


def test_enum_suggestion_pattern_group_requires_multiple_values():
    facts = Facts(project_path="x")
    facts.string_literals = [
        StringLiteral(value="pending", occurrences=[("app/Services/A.php", 11), ("app/Services/B.php", 22)]),
        StringLiteral(value="completed", occurrences=[("app/Services/C.php", 33), ("app/Services/D.php", 44)]),
    ]

    rule = EnumSuggestionRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings
    assert any(f.rule_id == "enum-suggestion" for f in findings)


def test_enum_suggestion_skips_when_matching_enum_already_exists():
    facts = Facts(project_path="x")
    facts.enums.append(
        ClassInfo(
            name="StatusEnum",
            fqcn="App\\Enums\\StatusEnum",
            file_path="app/Enums/StatusEnum.php",
            file_hash="deadbeef",
            line_start=1,
            line_end=20,
        )
    )
    facts.string_literals = [
        StringLiteral(value="pending", occurrences=[("a.php", 10), ("b.php", 20)]),
        StringLiteral(value="completed", occurrences=[("a.php", 30), ("b.php", 40)]),
    ]

    rule = EnumSuggestionRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings
    assert all(f.rule_id != "enum-suggestion" for f in findings)


def test_enum_suggestion_skips_when_matching_enum_file_exists_in_facts_files():
    facts = Facts(project_path="x")
    facts.files = ["app/Enums/StatusEnum.php"]
    facts.string_literals = [
        StringLiteral(value="pending", occurrences=[("a.php", 10), ("b.php", 20)]),
        StringLiteral(value="completed", occurrences=[("a.php", 30), ("b.php", 40)]),
    ]

    rule = EnumSuggestionRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings
    assert all(f.rule_id != "enum-suggestion" for f in findings)


def test_string_literal_collection_extracts_comparison_context_for_enum_detection():
    from analysis.facts_builder import FactsBuilder
    from core.detector import ProjectDetector
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "app" / "Http" / "Controllers").mkdir(parents=True)
        p = root / "app" / "Http" / "Controllers" / "OrderController.php"
        p.write_text(
            "<?php\n"
            "namespace App\\Http\\Controllers;\n"
            "class OrderController { public function show($order) { if ($order->status === 'pending') { return 'ok'; } } }\n",
            encoding="utf-8",
        )

        info = ProjectDetector(str(root)).detect()
        facts = FactsBuilder(info).build()

        pending_literal = next((s for s in facts.string_literals if s.value == "pending"), None)
        assert pending_literal is not None
        assert any((occ.context or "") == "status" for occ in pending_literal.occurrences)
