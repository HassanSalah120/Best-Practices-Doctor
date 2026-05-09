from pathlib import Path

import pytest

from analysis.facts_builder import FactsBuilder
from core.detector import ProjectDetector
from core.rule_engine import ALL_RULES, create_engine
from core.ruleset import RuleConfig, Ruleset


def _ruleset_for(rule_ids: list[str]) -> Ruleset:
    rules = {rid: RuleConfig(enabled=False) for rid in ALL_RULES.keys()}
    for rule_id in rule_ids:
        rules[rule_id] = RuleConfig(enabled=True)
    return Ruleset(rules=rules, name="balanced")


def _build_fixture(fixture_path: Path, fixture_name: str):
    project_root = fixture_path / fixture_name
    info = ProjectDetector(str(project_root)).detect()
    facts = FactsBuilder(info).build()
    return project_root, info, facts


@pytest.mark.parametrize(
    ("fixture_name", "rule_ids"),
    [
        (
            "react-intentional-colocation-mini",
            [
                "react-project-structure-consistency",
                "inertia-page-missing-head",
                "hardcoded-user-facing-strings",
            ],
        ),
        (
            "laravel-non-tenant-account-mini",
            [
                "tenant-scope-enforcement",
                "tenant-access-middleware-missing",
            ],
        ),
        ("laravel-auth-light-mini", ["controller-inline-validation"]),
        ("laravel-custom-exception-mini", ["custom-exception-suggestion"]),
        ("laravel-demo-secrets-mini", ["hardcoded-secrets"]),
    ],
)
def test_negative_fixture_packs_produce_no_findings(fixture_path: Path, fixture_name: str, rule_ids: list[str]):
    _, info, facts = _build_fixture(fixture_path, fixture_name)
    engine = create_engine(ruleset=_ruleset_for(rule_ids), selected_rules=rule_ids)
    result = engine.run(facts, project_type=info.project_type.value)

    assert result.findings == [], [finding.rule_id for finding in result.findings]


def test_project_context_detects_intentional_react_colocation(fixture_path: Path):
    _, _, facts = _build_fixture(fixture_path, "react-intentional-colocation-mini")

    assert facts.project_context.react_structure_mode == "hybrid"
    assert facts.project_context.has_i18n is True
    assert "AppSeo" in facts.project_context.custom_head_wrappers
    assert "components" in facts.project_context.react_shared_roots


def test_project_context_detects_non_tenant_account_wording(fixture_path: Path):
    _, _, facts = _build_fixture(fixture_path, "laravel-non-tenant-account-mini")

    assert facts.project_context.tenant_mode == "non_tenant"


def test_project_context_detects_auth_flow_exceptions(fixture_path: Path):
    _, _, facts = _build_fixture(fixture_path, "laravel-auth-light-mini")

    auth_paths = set(facts.project_context.auth_flow_paths)
    assert "app/Http/Controllers/Auth/LoginController.php" in auth_paths
