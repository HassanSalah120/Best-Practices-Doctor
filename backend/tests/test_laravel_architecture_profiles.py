from pathlib import Path

import pytest

from analysis.facts_builder import FactsBuilder
from analysis.metrics_analyzer import MetricsAnalyzer
from core.detector import ProjectDetector
from core.rule_engine import ALL_RULES, create_engine
from core.ruleset import RuleConfig, Ruleset
from core.scoring import ScoringEngine


def _ruleset_for(rule_ids: list[str]) -> Ruleset:
    rules = {rid: RuleConfig(enabled=False) for rid in ALL_RULES.keys()}
    for rule_id in rule_ids:
        rules[rule_id] = RuleConfig(enabled=True)
    return Ruleset(rules=rules, name="balanced")


def _build_fixture(fixture_path: Path, fixture_name: str):
    project_root = fixture_path / fixture_name
    info = ProjectDetector(str(project_root)).detect()
    facts = FactsBuilder(info).build()
    metrics = MetricsAnalyzer().analyze(facts)
    return info, facts, metrics


def _run_fixture(fixture_path: Path, fixture_name: str, rule_ids: list[str]):
    info, facts, metrics = _build_fixture(fixture_path, fixture_name)
    engine = create_engine(ruleset=_ruleset_for(rule_ids), selected_rules=rule_ids)
    result = engine.run(facts, metrics=metrics, project_type=info.project_type.value)
    return info, facts, metrics, result


@pytest.mark.parametrize(
    ("fixture_name", "expected_profile"),
    [
        ("laravel-mvc-valid-mini", "mvc"),
        ("laravel-mvc-near-miss-mini", "mvc"),
        ("laravel-mvc-invalid-mini", "mvc"),
        ("laravel-layered-no-dto-mini", "layered"),
        ("laravel-layered-actions-no-repository-mini", "layered"),
        ("laravel-layered-invalid-mini", "layered"),
        ("laravel-modular-valid-mini", "modular"),
        ("laravel-modular-near-miss-mini", "modular"),
        ("laravel-modular-invalid-mini", "modular"),
        ("laravel-api-first-valid-mini", "api-first"),
        ("laravel-api-first-near-miss-mini", "api-first"),
        ("laravel-api-first-invalid-mini", "api-first"),
    ],
)
def test_laravel_backend_profile_detection(fixture_path: Path, fixture_name: str, expected_profile: str):
    info, facts, _ = _build_fixture(fixture_path, fixture_name)

    assert info.project_type.value.startswith("laravel")
    assert facts.project_context.backend_framework == "laravel"
    assert facts.project_context.backend_architecture_profile == expected_profile
    assert facts.project_context.backend_profile_signals
    assert facts.project_context.backend_profile_confidence > 0
    assert facts.project_context.backend_profile_confidence_kind in {"structural", "heuristic"}
    assert facts.project_context.backend_profile_debug.get("selected_profile") == expected_profile


@pytest.mark.parametrize(
    "fixture_name",
    [
        "laravel-mvc-valid-mini",
        "laravel-mvc-near-miss-mini",
        "laravel-layered-no-dto-mini",
        "laravel-layered-actions-no-repository-mini",
        "laravel-modular-valid-mini",
        "laravel-modular-near-miss-mini",
        "laravel-api-first-valid-mini",
        "laravel-api-first-near-miss-mini",
    ],
)
def test_valid_and_near_miss_laravel_profiles_stay_quiet(fixture_path: Path, fixture_name: str):
    _, _, _, result = _run_fixture(
        fixture_path,
        fixture_name,
        ["controller-business-logic", "service-extraction", "too-many-dependencies", "god-class"],
    )

    assert result.findings == [], [f"{finding.rule_id}:{finding.file}" for finding in result.findings]


@pytest.mark.parametrize(
    ("fixture_name", "expected_rules"),
    [
        ("laravel-mvc-invalid-mini", {"controller-business-logic", "service-extraction"}),
        ("laravel-layered-invalid-mini", {"controller-business-logic", "service-extraction"}),
        ("laravel-modular-invalid-mini", {"controller-business-logic", "service-extraction"}),
        ("laravel-api-first-invalid-mini", {"controller-business-logic", "service-extraction"}),
    ],
)
def test_invalid_laravel_profile_examples_still_flag_real_violations(
    fixture_path: Path,
    fixture_name: str,
    expected_rules: set[str],
):
    _, facts, _, result = _run_fixture(
        fixture_path,
        fixture_name,
        ["controller-business-logic", "service-extraction"],
    )

    rule_ids = {finding.rule_id for finding in result.findings}
    assert expected_rules.issubset(rule_ids)
    for finding in result.findings:
        assert finding.metadata
        decision = finding.metadata.get("decision_profile", {})
        if decision:
            assert decision.get("architecture_profile") == facts.project_context.backend_architecture_profile


def test_mvc_service_injection_is_not_misclassified_as_layered(fixture_path: Path):
    _, facts, _, result = _run_fixture(
        fixture_path,
        "laravel-mvc-near-miss-mini",
        ["controller-business-logic", "service-extraction"],
    )

    assert facts.project_context.backend_architecture_profile == "mvc"
    assert result.findings == []


def test_api_first_response_orchestration_is_accepted_but_inline_business_logic_is_not(fixture_path: Path):
    _, valid_facts, _, valid_result = _run_fixture(
        fixture_path,
        "laravel-api-first-near-miss-mini",
        ["controller-business-logic", "service-extraction"],
    )
    _, invalid_facts, _, invalid_result = _run_fixture(
        fixture_path,
        "laravel-api-first-invalid-mini",
        ["controller-business-logic", "service-extraction"],
    )

    assert valid_facts.project_context.backend_architecture_profile == "api-first"
    assert valid_result.findings == []
    assert invalid_facts.project_context.backend_architecture_profile == "api-first"
    assert {finding.rule_id for finding in invalid_result.findings} >= {
        "controller-business-logic",
        "service-extraction",
    }


def test_modular_laravel_is_distinct_from_generic_layered_laravel(fixture_path: Path):
    _, modular_facts, _, modular_result = _run_fixture(
        fixture_path,
        "laravel-modular-valid-mini",
        ["controller-business-logic", "service-extraction"],
    )
    _, layered_facts, _, layered_result = _run_fixture(
        fixture_path,
        "laravel-layered-no-dto-mini",
        ["controller-business-logic", "service-extraction"],
    )

    assert modular_facts.project_context.backend_architecture_profile == "modular"
    assert layered_facts.project_context.backend_architecture_profile == "layered"
    assert modular_result.findings == []
    assert layered_result.findings == []


def test_laravel_profile_debug_payload_exposes_framework_profile_and_signals(fixture_path: Path):
    _, facts, _ = _build_fixture(fixture_path, "laravel-api-first-valid-mini")

    payload = facts.project_context.backend_debug_payload()

    assert payload["backend_framework"] == "laravel"
    assert payload["architecture_profile"] == "api-first"
    assert payload["profile_confidence"] > 0
    assert payload["profile_confidence_kind"] in {"structural", "heuristic"}
    assert payload["profile_signals"]
    assert payload["profile_debug"]["selected_profile"] == "api-first"


def test_scan_report_exposes_project_context_debug(fixture_path: Path):
    info, facts, _, result = _run_fixture(
        fixture_path,
        "laravel-layered-no-dto-mini",
        ["controller-business-logic", "service-extraction"],
    )
    report = ScoringEngine(_ruleset_for(["controller-business-logic", "service-extraction"])).generate_report(
        job_id="job_debug",
        project_path=str(fixture_path / "laravel-layered-no-dto-mini"),
        findings=result.findings,
        facts=facts,
        project_info=info,
        ruleset_path="balanced",
        rules_executed=["controller-business-logic", "service-extraction"],
    )

    project_debug = report.analysis_debug["project_context"]
    assert project_debug["backend_framework"] == "laravel"
    assert project_debug["backend_architecture_profile"] == "layered"
    assert project_debug["backend_profile_confidence"] > 0
    assert project_debug["backend_profile_confidence_kind"] in {"structural", "heuristic"}
    assert project_debug["backend_profile_signals"]
    assert project_debug["project_business_context"] in {
        "unknown",
        "saas_platform",
        "internal_admin_system",
        "clinic_erp_management",
        "api_backend",
        "realtime_game_control_platform",
        "public_website_with_dashboard",
        "portal_based_business_app",
    }
    assert "backend_capabilities" in project_debug
    assert isinstance(project_debug["backend_capabilities"], dict)
    assert "backend_team_expectations" in project_debug
    assert isinstance(project_debug["backend_team_expectations"], dict)


def test_profile_aware_laravel_findings_include_explainable_reasoning(fixture_path: Path):
    _, facts, _, result = _run_fixture(
        fixture_path,
        "laravel-layered-invalid-mini",
        ["controller-business-logic", "service-extraction"],
    )

    by_rule = {finding.rule_id: finding for finding in result.findings}
    controller_finding = by_rule["controller-business-logic"]
    service_finding = by_rule["service-extraction"]

    controller_debug = controller_finding.metadata["decision_profile"]
    assert controller_debug["architecture_profile"] == facts.project_context.backend_architecture_profile
    assert controller_debug["decision"] == "emit"
    assert controller_debug["decision_summary"]
    assert controller_debug["profile_confidence_kind"] in {"structural", "heuristic"}
    assert controller_debug["profile_signals"]
    assert "severity_from" in controller_debug
    assert "severity_to" in controller_debug
    assert "severity_reason" in controller_debug
    assert "recommendation_basis" in controller_debug
    assert any(signal.startswith("profile_confidence_kind=") for signal in controller_finding.evidence_signals)

    service_debug = service_finding.metadata["decision_profile"]
    assert service_debug["architecture_profile"] == facts.project_context.backend_architecture_profile
    assert service_debug["decision"] == "emit"
    assert service_debug["decision_summary"]
    assert service_debug["profile_confidence_kind"] in {"structural", "heuristic"}
    assert service_debug["profile_signals"]
    assert "severity_from" in service_debug
    assert "severity_to" in service_debug
    assert "severity_reason" in service_debug
    assert "recommendation_basis" in service_debug
    assert any(signal.startswith("profile_confidence_kind=") for signal in service_finding.evidence_signals)
