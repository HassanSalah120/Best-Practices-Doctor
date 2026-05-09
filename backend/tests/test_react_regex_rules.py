from pathlib import Path

from core.rule_engine import ALL_RULES, RuleEngine
from core.ruleset import RuleConfig, Ruleset
from rules.react.no_array_index_key import NoArrayIndexKeyRule
from rules.react.useeffect_dependency_array import UseEffectDependencyArrayRule
from schemas.facts import Facts


def test_useeffect_dependency_array_positive_and_negative():
    rule = UseEffectDependencyArrayRule(RuleConfig())
    facts = Facts(project_path="x")

    pos = """
import { useEffect } from 'react';
export function A() {
  useEffect(() => {
    fetch('/api/patients');
  });
  return null;
}
"""
    neg = """
import { useEffect } from 'react';
export function A() {
  useEffect(() => {
    fetch('/api/patients');
  }, []);
  return null;
}
"""
    suppressed = """
import { useEffect } from 'react';
export function A() {
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    fetch('/api/patients');
  });
  return null;
}
"""

    assert rule.analyze_regex("resources/js/Pages/A.tsx", pos, facts)
    assert not rule.analyze_regex("resources/js/Pages/A.tsx", neg, facts)
    assert not rule.analyze_regex("resources/js/Pages/A.tsx", suppressed, facts)


def test_react_no_array_index_key_positive_and_negative():
    rule = NoArrayIndexKeyRule(RuleConfig())
    facts = Facts(project_path="x")

    pos = "return items.map((item, index) => <li key={index}>{item.name}</li>);"
    neg = "return items.map((item) => <li key={item.id}>{item.name}</li>);"

    assert rule.analyze_regex("resources/js/Components/List.tsx", pos, facts)
    assert not rule.analyze_regex("resources/js/Components/List.tsx", neg, facts)


def test_react_no_array_index_key_skips_composite_key_with_extra_stable_signal():
    rule = NoArrayIndexKeyRule(RuleConfig())
    facts = Facts(project_path="x")

    composite = "return logs.map((log, i) => <div key={`log-${i}-${log.substring(0, 10)}`}>{log}</div>);"
    assert not rule.analyze_regex("resources/js/Pages/Admin/Dashboard.tsx", composite, facts)


def test_rule_engine_runs_react_regex_rules_for_tsx_files(tmp_path: Path):
    root = tmp_path / "proj"
    page = root / "resources" / "js" / "Pages" / "Patients.tsx"
    page.parent.mkdir(parents=True, exist_ok=True)
    page.write_text(
        """
import { useEffect } from 'react';
export function PatientsPage() {
  useEffect(() => {
    fetch('/api/patients');
  });
  return <ul>{[1, 2].map((x, index) => <li key={index}>{x}</li>)}</ul>;
}
""",
        encoding="utf-8",
    )

    rules = {rid: RuleConfig(enabled=False) for rid in ALL_RULES.keys()}
    rules["react-useeffect-deps"] = RuleConfig(enabled=True)
    rules["react-no-array-index-key"] = RuleConfig(enabled=True)
    engine = RuleEngine(Ruleset(rules=rules))

    facts = Facts(project_path=str(root))
    facts.files = ["resources/js/Pages/Patients.tsx"]

    res = engine.run(facts, project_type="laravel_inertia_react")
    rule_ids = [f.rule_id for f in res.findings]
    assert "react-useeffect-deps" in rule_ids
    assert "react-no-array-index-key" in rule_ids
