from __future__ import annotations

from pathlib import Path

from analysis.facts_builder import FactsBuilder
from analysis.metrics_analyzer import MetricsAnalyzer
from core.detector import ProjectDetector
from core.rule_engine import ALL_RULES, create_engine
from core.ruleset import RuleConfig, Ruleset


def _ruleset_for(rule_ids: list[str]) -> Ruleset:
    rules = {rid: RuleConfig(enabled=False) for rid in ALL_RULES.keys()}
    for rule_id in rule_ids:
        rules[rule_id] = RuleConfig(enabled=True)
    return Ruleset(rules=rules, name="balanced")


def _run_fixture(fixture_path: Path, fixture_name: str, rule_ids: list[str]):
    project_root = fixture_path / fixture_name
    info = ProjectDetector(str(project_root)).detect()
    facts = FactsBuilder(info).build()
    metrics = MetricsAnalyzer().analyze(facts)
    engine = create_engine(ruleset=_ruleset_for(rule_ids), selected_rules=rule_ids)
    result = engine.run(facts, metrics=metrics, project_type=info.project_type.value)
    return info, facts, metrics, result


def test_schema_governance_invalid_fixture_flags_new_rule_family(fixture_path: Path):
    rule_ids = [
        "missing-foreign-key-in-migration",
        "missing-index-on-lookup-columns",
        "destructive-migration-without-safety-guard",
        "model-hidden-sensitive-attributes-missing",
        "sensitive-model-appends-risk",
        "public-api-versioning-missing",
    ]
    _, _, _, result = _run_fixture(fixture_path, "laravel-schema-governance-invalid-mini", rule_ids)

    emitted = {finding.rule_id for finding in result.findings}
    assert emitted >= set(rule_ids)


def test_schema_governance_valid_fixture_stays_quiet(fixture_path: Path):
    rule_ids = [
        "missing-foreign-key-in-migration",
        "missing-index-on-lookup-columns",
        "destructive-migration-without-safety-guard",
        "model-hidden-sensitive-attributes-missing",
        "sensitive-model-appends-risk",
        "public-api-versioning-missing",
    ]
    _, _, _, result = _run_fixture(fixture_path, "laravel-schema-governance-valid-mini", rule_ids)

    assert result.findings == [], [f"{finding.rule_id}:{finding.file}" for finding in result.findings]


def test_async_communication_invalid_fixture_flags_new_and_existing_queue_rules(fixture_path: Path):
    new_rule_ids = [
        "notification-shouldqueue-missing",
        "listener-shouldqueue-missing-for-io-bound-handler",
        "broadcast-channel-authorization-missing",
        "observer-heavy-logic",
    ]
    legacy_queue_rule_ids = [
        "job-missing-idempotency-guard",
        "job-missing-retry-policy",
        "job-http-call-missing-timeout",
    ]
    _, _, _, result = _run_fixture(
        fixture_path,
        "laravel-async-communication-invalid-mini",
        new_rule_ids + legacy_queue_rule_ids,
    )

    emitted = {finding.rule_id for finding in result.findings}
    assert emitted >= set(new_rule_ids)


def test_async_communication_valid_fixture_stays_quiet(fixture_path: Path):
    rule_ids = [
        "notification-shouldqueue-missing",
        "listener-shouldqueue-missing-for-io-bound-handler",
        "broadcast-channel-authorization-missing",
        "observer-heavy-logic",
        "job-missing-idempotency-guard",
        "job-missing-retry-policy",
        "job-http-call-missing-timeout",
    ]
    _, _, _, result = _run_fixture(fixture_path, "laravel-async-communication-valid-mini", rule_ids)

    assert result.findings == [], [f"{finding.rule_id}:{finding.file}" for finding in result.findings]
