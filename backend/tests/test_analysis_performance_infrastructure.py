from __future__ import annotations

from pathlib import Path

import core.project_inventory as project_inventory
from analysis.facts_builder import FactsBuilder
from analysis.metrics_analyzer import MetricsAnalyzer
from core.detector import ProjectDetector
from core.pipeline.cache_signatures import stable_signature
from core.pipeline.stage_cache import StageCacheManager
from core.rule_engine import ALL_RULES, RuleEngine
from core.ruleset import RuleConfig, Ruleset
from schemas.facts import Facts


def _ruleset_with_enabled(*rule_ids: str) -> Ruleset:
    rules = {rule_id: RuleConfig(enabled=False) for rule_id in ALL_RULES}
    for rule_id in rule_ids:
        rules[rule_id] = RuleConfig(enabled=True)
    return Ruleset(rules=rules, name="performance-test")


def test_detector_and_facts_builder_share_one_project_walk(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "Controller.php").write_text("<?php class Controller {}", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "App.tsx").write_text("export const App = () => <main />;", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"dependencies":{"react":"^19"}}', encoding="utf-8")

    real_walk = project_inventory.os.walk
    calls = 0

    def counting_walk(*args, **kwargs):
        nonlocal calls
        calls += 1
        return real_walk(*args, **kwargs)

    monkeypatch.setattr(project_inventory.os, "walk", counting_walk)

    info = ProjectDetector(tmp_path).detect()
    facts = FactsBuilder(info).build()

    assert calls == 1
    assert set(info.discovered_files) >= {"app/Controller.php", "src/App.tsx", "package.json"}
    assert facts.analysis_stats["inventory_files"] == len(info.discovered_files)


def test_rule_engine_reads_each_matching_source_once(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "routes.php").write_text(
        "<?php\nRoute::get('/health', fn () => 'ok');\nLog::debug('trace');\n",
        encoding="utf-8",
    )
    (tmp_path / "frontend").mkdir()
    ts_files = []
    for index in range(25):
        rel_path = f"frontend/Component{index}.tsx"
        (tmp_path / rel_path).write_text("export const C = () => <div />;", encoding="utf-8")
        ts_files.append(rel_path)

    facts = Facts(project_path=str(tmp_path), files=["app/routes.php", *ts_files])
    result = RuleEngine(
        _ruleset_with_enabled("no-closure-routes", "no-log-debug-in-app"),
    ).run(facts, project_type="laravel_api")

    source_stats = result.analysis_stats["source_store"]
    assert source_stats["candidate_files"] == 26
    assert source_stats["disk_reads"] == 1
    assert source_stats["cache_hits"] >= 1
    assert result.analysis_stats["regex_rule_file_pairs"] == 2


def test_effective_ruleset_signature_changes_with_thresholds() -> None:
    first = Ruleset(rules={"long-method": RuleConfig(enabled=True, thresholds={"max_loc": 40})})
    second = Ruleset(rules={"long-method": RuleConfig(enabled=True, thresholds={"max_loc": 80})})

    assert stable_signature(first) != stable_signature(second)


def test_ruleset_yaml_cache_invalidates_when_file_changes(tmp_path: Path) -> None:
    path = tmp_path / "ruleset.yaml"
    path.write_text("name: first\nrules: {}\n", encoding="utf-8")
    first = Ruleset.load(path)
    path.write_text("name: second-profile\nrules: {}\n", encoding="utf-8")
    second = Ruleset.load(path)

    assert first.name == "first"
    assert second.name == "second-profile"


def test_metrics_parser_reads_multi_method_php_file_once(tmp_path: Path) -> None:
    source = tmp_path / "Service.php"
    source.write_text(
        """<?php
class Service {
    public function first(bool $ok) { if ($ok) { return 1; } return 0; }
    public function second(array $rows) { foreach ($rows as $row) { echo $row; } }
}
""",
        encoding="utf-8",
    )
    facts = FactsBuilder(ProjectDetector(tmp_path).detect()).build()

    MetricsAnalyzer().analyze(facts)

    stats = facts.analysis_stats["metrics"]
    assert stats["method_count"] == 2
    assert stats["complexity_file_reads"] == 1
    assert stats["complexity_cache_hits"] == 1


def test_stage_manifest_prunes_nested_generated_directories(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("BPD_APP_DATA_DIR", str(tmp_path / "app-data"))
    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    (project / "src" / "App.tsx").write_text("export const App = () => null;", encoding="utf-8")
    generated = project / "packages" / "ui" / "node_modules" / "lib"
    generated.mkdir(parents=True)
    for index in range(20):
        (generated / f"generated-{index}.js").write_text("generated", encoding="utf-8")

    manager = StageCacheManager(str(project))
    manager.compute_manifest_hash()

    assert manager.get_stats()["manifest"]["files_hashed"] == 1


def test_stage_manifest_keeps_environment_files_for_correct_invalidation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("BPD_APP_DATA_DIR", str(tmp_path / "app-data"))
    project = tmp_path / "project"
    project.mkdir()
    (project / ".env").write_text("APP_DEBUG=false\n", encoding="utf-8")

    manager = StageCacheManager(str(project))

    assert manager.get_project_inventory() == [".env"]
