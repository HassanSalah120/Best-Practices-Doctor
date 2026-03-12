from analysis.facts_builder import FactsBuilder
from core.detector import ProjectDetector


def test_facts_builder_registers_composer_and_package_files_for_regex_rules(fixture_path):
    laravel_root = fixture_path / "sample-lara"
    inertia_root = fixture_path / "laravel-inertia-react-mini"

    laravel_facts = FactsBuilder(ProjectDetector(str(laravel_root)).detect()).build()
    inertia_facts = FactsBuilder(ProjectDetector(str(inertia_root)).detect()).build()

    assert "composer.json" in laravel_facts.files
    assert "composer.json" in inertia_facts.files
    assert "package.json" in inertia_facts.files
