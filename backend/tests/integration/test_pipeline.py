import pytest
from pathlib import Path

from core.detector import ProjectDetector
from analysis.facts_builder import FactsBuilder
from analysis.metrics_analyzer import MetricsAnalyzer
from core.rule_engine import create_engine
from core.scoring import ScoringEngine
from schemas.project_type import ProjectInfo

def test_full_pipeline_sample_lara(fixture_path):
    """Verify end-to-end analysis on the sample-lara fixture."""
    project_root = fixture_path / "sample-lara"
    
    detector = ProjectDetector(str(project_root))
    project_info = detector.detect()
    assert "laravel" in project_info.project_type.value
    
    # 2. Raw Facts
    builder = FactsBuilder(project_info)
    # Mocking wait for builder if needed, but it's usually synchronous in tests
    raw_facts = builder.build()
    
    assert len(raw_facts.classes) >= 1
    # UserController should be found
    user_controller = next((c for c in raw_facts.classes if c.name == "UserController"), None)
    assert user_controller is not None
    assert "store" in [m.name for m in raw_facts.methods if m.class_name == "UserController"]
    
    # 3. Derived Metrics
    analyzer = MetricsAnalyzer()
    metrics = analyzer.analyze(raw_facts)
    
    # 4. Rules
    engine = create_engine()
    # engine.run expects (facts, metrics, project_type, cancellation_check)
    engine_result = engine.run(raw_facts, metrics, project_info.project_type.value)
    findings = engine_result.findings
    
    # Should have some findings (fat-controller or other rules)
    # Note: fat-controller threshold may require more complex code than fixture provides
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}. Findings: {[f.rule_id for f in findings]}"
    
    # 5. Scoring
    scorer = ScoringEngine()
    # ScoringEngine.calculate expects (findings, file_count, method_count)
    scoring_result = scorer.calculate(
        findings,
        file_count=builder.progress.total_files,
        method_count=len(raw_facts.methods)
    )
    # report = scorer.generate_report(...) exists but we should ensure overall score check matches schemas
    report = scorer.generate_report("test-job", str(project_root), findings, raw_facts, project_info=project_info)
    
    assert report.scores.overall < 100  # Should have deductions
    assert report.files_scanned >= 1
    assert "laravel" in report.project_info.project_type.value
    assert any(f.file.endswith("UserController.php") for f in report.findings)

def test_pipeline_with_ignore_globs(fixture_path):
    """Verify that ignore globs correctly filter facts."""
    project_root = fixture_path / "sample-lara"
    
    # Custom ignore to filter out Controllers
    project_info = ProjectInfo(root_path=str(project_root), type="laravel")
    builder = FactsBuilder(project_info, ignore_patterns=["**/Controllers/**"])
    raw_facts = builder.build()
    
    # Controllers should not be in the facts now
    assert not any("Controllers" in c.file_path for c in raw_facts.classes)
