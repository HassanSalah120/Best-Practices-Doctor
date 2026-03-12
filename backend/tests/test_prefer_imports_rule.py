import tempfile
from pathlib import Path

from analysis.facts_builder import FactsBuilder
from core.detector import ProjectDetector
from core.ruleset import RuleConfig
from rules.php.prefer_imports import PreferImportsRule


def _run(rule: PreferImportsRule, root: Path):
    info = ProjectDetector(str(root)).detect()
    facts = FactsBuilder(info).build()
    return rule.run(facts, project_type=info.project_type.value, metrics={})


def test_prefer_imports_flags_fqcn_in_new_expression():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "app" / "Http" / "Controllers").mkdir(parents=True)

        (root / "app" / "Http" / "Controllers" / "FooController.php").write_text(
            "<?php\n"
            "namespace App\\Http\\Controllers;\n"
            "class FooController {\n"
            "  public function __invoke() {\n"
            "    $x = new \\App\\Services\\UserService();\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )

        res = _run(PreferImportsRule(RuleConfig()), root)
        assert any(f.rule_id == "prefer-imports" for f in res.findings)
        f = next(f for f in res.findings if f.rule_id == "prefer-imports")
        assert f.file == "app/Http/Controllers/FooController.php"
        assert f.context == "App\\Services\\UserService"


def test_prefer_imports_does_not_flag_when_already_imported_and_short_name_used():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "app" / "Http" / "Controllers").mkdir(parents=True)

        (root / "app" / "Http" / "Controllers" / "FooController.php").write_text(
            "<?php\n"
            "namespace App\\Http\\Controllers;\n"
            "use App\\Services\\UserService;\n"
            "class FooController {\n"
            "  public function __invoke() {\n"
            "    $x = new UserService();\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )

        res = _run(PreferImportsRule(RuleConfig()), root)
        assert not any(f.rule_id == "prefer-imports" for f in res.findings)


def test_prefer_imports_does_not_flag_same_namespace_reference():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "app" / "Services").mkdir(parents=True)

        (root / "app" / "Services" / "Foo.php").write_text(
            "<?php\n"
            "namespace App\\Services;\n"
            "class Foo {\n"
            "  public function go() {\n"
            "    $x = new \\App\\Services\\UserService();\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )

        res = _run(PreferImportsRule(RuleConfig()), root)
        assert not any(f.rule_id == "prefer-imports" for f in res.findings)


def test_prefer_imports_does_not_flag_vendor_namespaces_by_default():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "app").mkdir(parents=True)

        (root / "app" / "Foo.php").write_text(
            "<?php\n"
            "namespace App;\n"
            "class Foo {\n"
            "  public function go() {\n"
            "    $x = new \\Illuminate\\Support\\Collection();\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )

        res = _run(PreferImportsRule(RuleConfig()), root)
        assert not any(f.rule_id == "prefer-imports" for f in res.findings)


def test_prefer_imports_flags_fqcn_in_type_hint():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "app").mkdir(parents=True)

        (root / "app" / "Foo.php").write_text(
            "<?php\n"
            "namespace App;\n"
            "function foo(\\App\\Services\\UserService $svc) {\n"
            "  return $svc;\n"
            "}\n",
            encoding="utf-8",
        )

        res = _run(PreferImportsRule(RuleConfig()), root)
        assert any(f.rule_id == "prefer-imports" for f in res.findings)
