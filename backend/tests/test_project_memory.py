from pathlib import Path

from core.project_memory import ProjectIntelligenceManager


def test_project_memory_status_and_factor(tmp_path: Path):
    manager = ProjectIntelligenceManager(app_data_dir=tmp_path)
    project_path = str(tmp_path / "demo-project")

    manager.record_finding_status(project_path, rule_id="god-class", status="skipped")
    manager.record_finding_status(project_path, rule_id="god-class", status="skipped")
    manager.record_finding_status(project_path, rule_id="god-class", status="fixed")
    memory = manager.get_project(project_path)
    stats = memory.rule_dispositions["god-class"]
    assert stats.total_updates == 3
    assert stats.skipped == 2
    assert stats.fixed == 1

    factor = manager.get_rule_memory_factor(project_path, "god-class")
    assert factor <= 1.0


def test_project_memory_context_and_baseline_tracking(tmp_path: Path):
    manager = ProjectIntelligenceManager(app_data_dir=tmp_path)
    project_path = str(tmp_path / "demo-project")

    manager.record_context_overrides(
        project_path,
        {"architecture_profile": "layered", "project_type": "saas_platform"},
    )
    manager.record_baseline_diff(project_path, new_count=4, resolved_count=2, unchanged_count=8)
    manager.record_suppression(project_path, rule_id="react-no-array-index-key")

    memory = manager.get_project(project_path)
    assert memory.architecture_preferences.get("layered", 0) >= 1
    assert memory.baseline_trends.get("new_total", 0) >= 4
    assert memory.suppression_counts_by_rule.get("react-no-array-index-key", 0) >= 1
