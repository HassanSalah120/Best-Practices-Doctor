from pathlib import Path

from core.pipeline.stage_cache import StageCacheManager


def test_stage_cache_save_and_load(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir(parents=True)
    (project / "app.py").write_text("print('ok')\n", encoding="utf-8")

    manager = StageCacheManager(str(project))
    payload = {"ruleset": "strict", "selected_rules": ["god-class"]}
    manager.save("detect_project", {"project_type": "python"}, payload)
    loaded = manager.load("detect_project", payload)

    assert loaded is not None
    assert loaded["project_type"] == "python"
    stats = manager.get_stats()
    assert stats["hits"].get("detect_project", 0) >= 1


def test_stage_cache_invalidates_on_manifest_change(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir(parents=True)
    target = project / "a.txt"
    target.write_text("one\n", encoding="utf-8")

    manager = StageCacheManager(str(project))
    payload = {"k": "v"}
    manager.save("build_facts", {"files": 1}, payload)
    assert manager.load("build_facts", payload) is not None

    target.write_text("two\n", encoding="utf-8")
    manager2 = StageCacheManager(str(project))
    assert manager2.load("build_facts", payload) is None
