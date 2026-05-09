import pytest
import time
from pathlib import Path

from analysis.facts_builder import FactsBuilder
from analysis.metrics_analyzer import MetricsAnalyzer
from core.detector import ProjectDetector
from core.rule_engine import create_engine
from schemas.project_type import ProjectInfo

def test_ignore_globs_precision(fixture_path):
    """Verify that specific subdirectories are ignored correctly."""
    project_root = fixture_path / "sample-lara"
    
    # 1. Standard build
    project_info = ProjectInfo(root_path=str(project_root), type="laravel")
    builder = FactsBuilder(project_info)
    facts = builder.build()
    assert any("UserController.php" in c.file_path for c in facts.classes)

    # 2. Build with specific ignore
    project_info_ignored = ProjectInfo(root_path=str(project_root), type="laravel")
    builder_ignored = FactsBuilder(project_info_ignored, ignore_patterns=["**/app/Http/Controllers/**"])
    facts_ignored = builder_ignored.build()
    assert not any("UserController.php" in c.file_path for c in facts_ignored.classes)

def test_analysis_performance(fixture_path):
    """Basic performance benchmark for facts building."""
    project_root = fixture_path / "sample-lara"
    project_info = ProjectInfo(root_path=str(project_root), type="laravel")
    builder = FactsBuilder(project_info)
    
    start_time = time.perf_counter()
    facts = builder.build()
    end_time = time.perf_counter()
    
    duration = end_time - start_time
    # For a small fixture, it should be sub-second
    assert duration < 4.0, f"Analysis took too long: {duration}s"
    assert len(facts.classes) > 0


def test_full_pipeline_performance(fixture_path):
    """Basic performance benchmark for full pipeline (facts + metrics + rules)."""
    project_root = fixture_path / "sample-lara"

    info = ProjectDetector(str(project_root)).detect()
    builder = FactsBuilder(info)

    t0 = time.perf_counter()
    facts = builder.build()
    metrics = MetricsAnalyzer().analyze(facts)
    engine = create_engine()
    _ = engine.run(facts, metrics, info.project_type.value)
    dt = time.perf_counter() - t0

    # Keep this threshold conservative for CI variability.
    assert dt < 10.0, f"Full pipeline took too long: {dt}s"
