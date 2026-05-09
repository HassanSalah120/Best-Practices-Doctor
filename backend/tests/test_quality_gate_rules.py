from __future__ import annotations

from pathlib import Path

from analysis.facts_builder import FactsBuilder
from analysis.metrics_analyzer import MetricsAnalyzer
from core.detector import ProjectDetector
from core.rule_engine import create_engine
from core.ruleset import Ruleset


def _run_engine(project_root: Path):
    info = ProjectDetector(str(project_root)).detect()
    facts = FactsBuilder(info).build()
    metrics = MetricsAnalyzer().analyze(facts)
    engine = create_engine(ruleset=Ruleset.load_default())
    result = engine.run(facts, metrics, info.project_type.value)
    return result.findings


def test_tests_missing_rule_positive_and_negative(fixture_path: Path):
    sample = fixture_path / "sample-lara"
    native = fixture_path / "php-native-mini"

    sample_findings = _run_engine(sample)
    native_findings = _run_engine(native)

    assert not any(f.rule_id == "tests-missing" for f in sample_findings), "sample-lara should have tests"
    assert any(f.rule_id == "tests-missing" for f in native_findings), "php-native-mini should trigger tests-missing"


def test_low_coverage_files_rule_positive_and_negative(fixture_path: Path):
    sample = fixture_path / "sample-lara"
    native = fixture_path / "php-native-mini"

    sample_findings = _run_engine(sample)
    native_findings = _run_engine(native)

    assert any(f.rule_id == "low-coverage-files" for f in sample_findings), "sample-lara should include clover.xml"
    assert not any(f.rule_id == "low-coverage-files" for f in native_findings), "no coverage artifacts expected"

