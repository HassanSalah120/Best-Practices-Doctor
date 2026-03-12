from pathlib import Path

from analysis.facts_builder import FactsBuilder
from core.detector import ProjectDetector
from rules.php.tests_missing import TestsMissingRule as MissingTestsRule
from core.ruleset import RuleConfig
from schemas.facts import Facts, ReactComponentInfo


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_detector_recognizes_react_test_scaffold_outside_tests_dir(tmp_path: Path):
    _write(
        tmp_path / "composer.json",
        '{"require":{"laravel/framework":"^10.0","php":"^8.2"},"require-dev":{}}',
    )
    _write(
        tmp_path / "package.json",
        '{"dependencies":{"react":"^18.0.0","@inertiajs/react":"^1.0.0"},"devDependencies":{"vitest":"^2.0.0"}}',
    )
    _write(tmp_path / "artisan", "")
    _write(tmp_path / "resources" / "js" / "Pages" / "Dashboard.tsx", "export default function Dashboard(){return <div/>}")
    _write(
        tmp_path / "resources" / "js" / "__tests__" / "Dashboard.test.tsx",
        "import { render } from '@testing-library/react';",
    )

    info = ProjectDetector(str(tmp_path)).detect()
    facts = FactsBuilder(info).build()

    assert info.has_tests is True
    assert facts.test_files_count == 1


def test_tests_missing_rule_uses_react_testing_guidance():
    facts = Facts(
        project_path=".",
        files=["package.json", "src/App.tsx"],
        react_components=[
            ReactComponentInfo(
                name="App",
                file_path="src/App.tsx",
                file_hash="deadbeef",
                line_start=1,
                line_end=10,
                loc=10,
            )
        ],
        has_tests=False,
        test_files_count=0,
    )

    findings = MissingTestsRule(RuleConfig()).run(facts).findings
    assert len(findings) == 1
    fix = findings[0].suggested_fix
    assert "Vitest or Jest" in fix
    assert "React Testing Library" in fix
    assert "PHPUnit or Pest" not in fix


def test_tests_missing_rule_description_is_not_phpunit_only():
    facts = Facts(project_path=".", files=["package.json"], has_tests=False, test_files_count=0)
    findings = MissingTestsRule(RuleConfig()).run(facts).findings
    assert len(findings) == 1
    assert "phpunit.xml" not in findings[0].description.lower()
    assert "__tests__" in findings[0].description
