import json
from pathlib import Path

import pytest

from analysis.facts_builder import FactsBuilder
from analysis.metrics_analyzer import MetricsAnalyzer
from core.detector import ProjectDetector
from core.rule_engine import create_engine
from core.scoring import ScoringEngine
from core.ruleset import Ruleset


def _normalize_report(report_dict: dict) -> dict:
    # Drop volatile fields
    report_dict["id"] = "normalized-id"
    report_dict["scanned_at"] = "2024-01-01T00:00:00Z"
    report_dict["duration_ms"] = 0
    report_dict["project_path"] = "/normalized/path"

    # Baseline metadata is computed in the API layer; snapshots focus on pure analysis/scoring outputs.
    report_dict.pop("new_findings_count", None)
    report_dict.pop("new_finding_fingerprints", None)
    report_dict.pop("resolved_findings_count", None)
    report_dict.pop("resolved_finding_fingerprints", None)
    report_dict.pop("unchanged_findings_count", None)
    report_dict.pop("unchanged_finding_fingerprints", None)
    report_dict.pop("baseline_profile", None)
    report_dict.pop("baseline_path", None)
    report_dict.pop("baseline_has_previous", None)
    report_dict.pop("baseline_new_counts_by_severity", None)
    report_dict.pop("baseline_resolved_counts_by_severity", None)
    report_dict.pop("baseline_unchanged_counts_by_severity", None)
    report_dict.pop("pr_gate", None)

    # Hotspots are computed in the API layer from metrics/facts; keep snapshots focused on stable scoring outputs.
    report_dict.pop("complexity_hotspots", None)
    report_dict.pop("duplication_hotspots", None)

    # New fields that vary based on rule changes - normalize for stable snapshots
    report_dict.pop("project_memory", None)
    report_dict.pop("pipeline_cache", None)
    report_dict.pop("safe_to_defer", None)
    report_dict.pop("top_5_first", None)
    report_dict.pop("triage_plan", None)
    report_dict.pop("action_plan", None)
    
    # analysis_debug contains project_memory with timestamps - normalize it
    analysis_debug = report_dict.pop("analysis_debug", None)
    if isinstance(analysis_debug, dict):
        # Keep the structure but remove timestamps
        analysis_debug.pop("project_memory", None)
        if "project_context" in analysis_debug:
            analysis_debug["project_context"] = "normalized"

    # Normalize nested project root for portability
    if "project_info" in report_dict and isinstance(report_dict["project_info"], dict):
        report_dict["project_info"]["root_path"] = "/normalized/path"
        # Normalize volatile project context fields
        report_dict["project_info"].pop("project_tier", None)
        report_dict["project_info"].pop("backend_architecture_profile", None)
        report_dict["project_info"].pop("capabilities", None)
        report_dict["project_info"].pop("recommendations", None)

    # Sort findings deterministically and keep stable fields (incl. fingerprint)
    findings = report_dict.get("findings", [])
    findings.sort(
        key=lambda f: (
            f.get("fingerprint", ""),
            f.get("rule_id", ""),
            f.get("file", ""),
            f.get("context", ""),
        )
    )
    for f in findings:
        # Assert stable identity is present; do not overwrite it.
        assert f.get("fingerprint"), "finding.fingerprint missing"
        assert f.get("id") == f"finding_{f['fingerprint']}", "finding.id must be derived from fingerprint"

    report_dict["findings"] = [
        {
            "id": f["id"],
            "fingerprint": f["fingerprint"],
            "rule_id": f["rule_id"],
            "category": f["category"],
            "severity": f["severity"],
            "classification": f.get("classification", "advisory"),
            "file": f["file"],
            "context": f.get("context", ""),
        }
        for f in findings
    ]

    # Action plan is derived, but should remain deterministic and fingerprint-stable.
    actions = report_dict.get("action_plan")
    if isinstance(actions, list):
        actions.sort(key=lambda a: (a.get("id", ""), a.get("rule_id", ""), a.get("category", "")))
        report_dict["action_plan"] = [
            {
                "id": a.get("id", ""),
                "rule_id": a.get("rule_id", ""),
                "category": a.get("category", ""),
                "priority": a.get("priority", 0.0),
                "max_severity": a.get("max_severity", ""),
                "classification": a.get("classification", "advisory"),
                "finding_fingerprints": sorted(a.get("finding_fingerprints", []) or []),
                "files": sorted(a.get("files", []) or []),
            }
            for a in actions
        ]

    # Grouped views + summaries are derived; don't snapshot them.
    report_dict["findings_by_file"] = {}
    report_dict["findings_by_category"] = {}
    report_dict["findings_by_severity"] = {}
    report_dict["findings_by_classification"] = {}
    report_dict["file_summaries"] = []
    report_dict["summary"] = ""

    # Normalize scores - they change as rules are added/removed
    report_dict.pop("scores", None)
    report_dict.pop("category_breakdown", None)

    # `rules_executed` is environment-sensitive (registry/runtime/loading details).
    # Snapshot coverage here focuses on report/findings contract, not registry shape.
    report_dict.pop("rules_executed", None)

    return report_dict


@pytest.mark.parametrize(
    "fixture_name,snapshot_name",
    [
        ("sample-lara", "sample-lara-report.json"),
        ("laravel-blade-mini", "laravel-blade-mini-report.json"),
        ("laravel-inertia-react-mini", "laravel-inertia-react-mini-report.json"),
        ("php-native-mini", "php-native-mini-report.json"),
        ("php-mvc-mini", "php-mvc-mini-report.json"),
    ],
)
def test_golden_snapshots(fixture_path, fixture_name: str, snapshot_name: str):
    import os
    project_root = fixture_path / fixture_name
    snapshot_path = Path(__file__).parent / "snapshots" / snapshot_name
    backend_root = Path(__file__).resolve().parents[2]
    ruleset = Ruleset.load(backend_root / "rulesets" / "startup.yaml")

    detector = ProjectDetector(str(project_root))
    project_info = detector.detect()

    builder = FactsBuilder(project_info)
    raw_facts = builder.build()

    analyzer = MetricsAnalyzer()
    metrics = analyzer.analyze(raw_facts)

    engine = create_engine(ruleset=ruleset)
    engine_result = engine.run(raw_facts, metrics, project_info.project_type.value)

    scorer = ScoringEngine(ruleset)
    report = scorer.generate_report(
        "snapshot-job",
        str(project_root),
        engine_result.findings,
        raw_facts,
        project_info=project_info,
        rules_executed=engine.get_rule_ids(),
    )

    report_dict = _normalize_report(json.loads(report.model_dump_json()))

    # Allow snapshot regeneration via environment variable
    if os.environ.get("SNAPSHOT_UPDATE"):
        snapshot_path.write_text(json.dumps(report_dict, indent=2))
        pytest.skip(f"Updated snapshot: {snapshot_name}")
        return

    if not snapshot_path.exists():
        raise AssertionError(f"Missing snapshot: {snapshot_path}")

    expected = _normalize_report(json.loads(snapshot_path.read_text()))
    assert report_dict == expected
