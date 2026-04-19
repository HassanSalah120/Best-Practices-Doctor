from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from analysis.facts_builder import FactsBuilder
from analysis.metrics_analyzer import MetricsAnalyzer
from core.context_profiles import ContextProfileMatrix
from core.detector import ProjectDetector
from core.rule_engine import ALL_RULES, create_engine
from core.ruleset import RuleConfig, Ruleset
from rules.react.inline_logic import InlineLogicRule
from rules.react.large_component import LargeComponentRule
from rules.react.missing_usecallback_for_event_handlers import MissingUseCallbackForEventHandlersRule
from rules.react.missing_usememo_for_expensive_calc import MissingUseMemoForExpensiveCalcRule
from rules.react.no_direct_useeffect import NoDirectUseEffectRule
from rules.react.no_inline_services import NoInlineServicesRule
from rules.react.project_structure_consistency import ReactProjectStructureConsistencyRule
from rules.react.useeffect_cleanup_missing import UseEffectCleanupMissingRule
from schemas.facts import Facts, ReactComponentInfo


BATCH_R1_RULES = [
    "react-project-structure-consistency",
    "no-inline-services",
    "inline-api-logic",
    "large-react-component",
    "no-direct-useeffect",
    "useeffect-cleanup-missing",
    "missing-usememo-for-expensive-calc",
    "missing-usecallback-for-event-handlers",
]


def _ruleset_for(rule_ids: list[str]) -> Ruleset:
    rules = {rid: RuleConfig(enabled=False) for rid in ALL_RULES.keys()}
    for rule_id in rule_ids:
        rules[rule_id] = RuleConfig(enabled=True)
    return Ruleset(rules=rules, name="strict")


def test_react_project_structure_consistency_batch_r1_valid_near_invalid():
    rule = ReactProjectStructureConsistencyRule(
        RuleConfig(
            thresholds={
                "min_candidates": 1,
                "min_placement_issues": 2,
                "allow_context_hybrid_shared_colocation": True,
                "suppress_when_context_pattern_matches": True,
            }
        )
    )

    valid = Facts(project_path=".")
    valid.files = [
        "resources/js/hooks/useEmailBooking.ts",
        "resources/js/layouts/PatientPortalLayout.utils.ts",
        "resources/js/pages/Patients/Create.utils.ts",
        "resources/js/pages/Patients/Create.tsx",
    ]
    valid.project_context.react_structure_mode = "hybrid"
    valid.project_context.react_shared_roots = ["hooks", "layouts"]
    assert rule.run(valid).findings == []

    near = Facts(project_path=".")
    near.files = [
        "resources/js/screens/admin/analytics/AnalyticsScreen.tsx",
        "resources/js/screens/admin/analytics/helpers/chartLabel.ts",
        "resources/js/lib/date/formatDuration.ts",
    ]
    near.project_context.react_structure_mode = "hybrid"
    near.project_context.react_shared_roots = ["lib", "screens"]
    assert rule.run(near).findings == []

    invalid = Facts(project_path=".")
    invalid.files = [
        "src/hooks/useAuth.ts",
        "src/features/appointment/useAppointment.ts",
        "src/pages/patients/services/patientService.ts",
        "src/lib/dateUtil.ts",
        "src/usePatients.ts",
        "src/appointmentService.ts",
        "src/shared/types/user.types.ts",
        "src/pages/auth/Login.tsx",
    ]
    findings = rule.run(invalid).findings
    assert findings
    assert any(f.rule_id == "react-project-structure-consistency" for f in findings)


def test_no_inline_services_batch_r1_valid_near_invalid():
    rule = NoInlineServicesRule(
        RuleConfig(
            thresholds={
                "min_service_like_helpers": 2,
                "local_glue_max_helpers": 1,
                "allow_page_shell_glue": True,
            }
        )
    )

    valid = Facts(project_path=".")
    valid.react_components.append(
        ReactComponentInfo(
            name="PortalScreen",
            file_path="resources/js/screens/live/PortalScreen.tsx",
            file_hash="a1",
            line_start=1,
            line_end=210,
            loc=210,
            has_inline_helper_fns=True,
            inline_helper_names=["submitRound"],
        )
    )
    valid._frontend_symbol_graph = {
        "files": {
            "resources/js/screens/live/PortalScreen.tsx": {
                "imports": [
                    "../../composables/usePortalScreenState",
                    "../../widgets/game/StagePanel",
                    "./lib/portalTimer",
                ]
            }
        }
    }
    valid.project_context.react_structure_mode = "hybrid"
    assert rule.analyze(valid) == []

    near = Facts(project_path=".")
    near.react_components.append(
        ReactComponentInfo(
            name="SettingsPage",
            file_path="resources/js/pages/Settings/Edit.tsx",
            file_hash="a2",
            line_start=1,
            line_end=180,
            loc=180,
            has_inline_helper_fns=True,
            inline_helper_names=["saveDraft"],
        )
    )
    near._frontend_symbol_graph = {
        "files": {
            "resources/js/pages/Settings/Edit.tsx": {
                "imports": ["../../hooks/useSettings", "../../components/FormSection"]
            }
        }
    }
    near.project_context.react_structure_mode = "hybrid"
    assert rule.analyze(near) == []

    invalid = Facts(project_path=".")
    invalid.react_components.append(
        ReactComponentInfo(
            name="BillingPage",
            file_path="resources/js/pages/Billing/Index.tsx",
            file_hash="a3",
            line_start=1,
            line_end=200,
            loc=200,
            has_inline_helper_fns=True,
            inline_helper_names=["fetchInvoices", "saveInvoice"],
        )
    )
    findings = rule.analyze(invalid)
    assert len(findings) == 1


def test_inline_api_logic_batch_r1_valid_near_invalid():
    rule = InlineLogicRule(
        RuleConfig(
            thresholds={
                "min_state_hook_count": 4,
                "suppress_query_hook_usage": True,
                "require_fetch_or_axios_for_api_finding": True,
            }
        )
    )

    tmp_root = Path("backend/tests/.tmp_react_batch_r1_inline") / str(uuid4())
    valid_path = tmp_root / "valid/resources/js/pages/Reports/ReportPage.tsx"
    valid_path.parent.mkdir(parents=True, exist_ok=True)
    valid_path.write_text(
        """import { useQuery } from '@tanstack/react-query';
export function ReportPage() {
  const { data } = useQuery(['reports'], () => Promise.resolve([]));
  return <div>{data?.length}</div>;
}
""",
        encoding="utf-8",
    )

    valid = Facts(project_path=str(tmp_root / "valid"))
    valid.react_components.append(
        ReactComponentInfo(
            name="ReportPage",
            file_path="resources/js/pages/Reports/ReportPage.tsx",
            file_hash="b1",
            line_start=1,
            line_end=5,
            loc=5,
            has_api_calls=True,
            hooks_used=["useQuery"],
        )
    )
    assert rule.analyze(valid) == []

    near_path = tmp_root / "near/resources/js/pages/Portal/Live.tsx"
    near_path.parent.mkdir(parents=True, exist_ok=True)
    near_path.write_text(
        """export function Live() {
  return <div>Live</div>;
}
""",
        encoding="utf-8",
    )
    near = Facts(project_path=str(tmp_root / "near"))
    near.react_components.append(
        ReactComponentInfo(
            name="Live",
            file_path="resources/js/pages/Portal/Live.tsx",
            file_hash="b2",
            line_start=1,
            line_end=3,
            loc=3,
            has_api_calls=True,
            hooks_used=["usePortalState"],
        )
    )
    near._frontend_symbol_graph = {
        "files": {
            "resources/js/pages/Portal/Live.tsx": {
                "imports": [
                    "../../hooks/usePortalState",
                    "../../services/liveService",
                    "../../components/LivePanel",
                ]
            }
        }
    }
    assert rule.analyze(near) == []

    invalid_path = tmp_root / "invalid/resources/js/pages/Users/UserPage.tsx"
    invalid_path.parent.mkdir(parents=True, exist_ok=True)
    invalid_path.write_text(
        """export function UserPage() {
  fetch('/api/users').then((r) => r.json());
  return <div>User page</div>;
}
""",
        encoding="utf-8",
    )
    invalid = Facts(project_path=str(tmp_root / "invalid"))
    invalid.react_components.append(
        ReactComponentInfo(
            name="UserPage",
            file_path="resources/js/pages/Users/UserPage.tsx",
            file_hash="b3",
            line_start=1,
            line_end=4,
            loc=4,
            has_api_calls=True,
            hooks_used=["useState"],
        )
    )
    findings = rule.analyze(invalid)
    assert len(findings) == 1


def test_large_react_component_batch_r1_valid_near_invalid():
    rule = LargeComponentRule(
        RuleConfig(
            thresholds={
                "max_lines": 220,
                "min_loc_to_consider": 200,
                "min_overflow_lines": 20,
                "max_lines_component_shell": 420,
                "max_lines_feature_shell": 520,
                "max_lines_composed_shell": 700,
                "max_lines_static_page": 420,
            }
        )
    )

    valid = Facts(project_path=".")
    valid.project_context.project_type = "realtime_game_control_platform"
    valid.project_context.capabilities = {"realtime": {"enabled": True, "confidence": 0.8, "source": "detected"}}
    valid.react_components.append(
        ReactComponentInfo(
            name="PortalScreen",
            file_path="resources/js/screens/live/PortalScreen.tsx",
            file_hash="c1",
            line_start=1,
            line_end=620,
            loc=620,
        )
    )
    valid._frontend_symbol_graph = {
        "files": {
            "resources/js/screens/live/PortalScreen.tsx": {
                "imports": [
                    "../../composables/usePortalScreenState",
                    "../../widgets/game/StagePanel",
                    "../../widgets/game/ResultsDrawer",
                ]
            }
        }
    }
    assert rule.analyze(valid) == []

    near = Facts(project_path=".")
    near.react_components.append(
        ReactComponentInfo(
            name="WelcomePage",
            file_path="resources/js/pages/Welcome.tsx",
            file_hash="c2",
            line_start=1,
            line_end=430,
            loc=430,
        )
    )
    near._frontend_symbol_graph = {"files": {"resources/js/pages/Welcome.tsx": {"imports": ["../../components/Hero"]}}}
    assert rule.analyze(near) == []

    invalid = Facts(project_path=".")
    invalid.react_components.append(
        ReactComponentInfo(
            name="AdminPanel",
            file_path="resources/js/components/AdminPanel.tsx",
            file_hash="c3",
            line_start=1,
            line_end=480,
            loc=480,
        )
    )
    findings = rule.analyze(invalid)
    assert len(findings) == 1


def test_no_direct_useeffect_batch_r1_valid_near_invalid():
    rule = NoDirectUseEffectRule(RuleConfig(thresholds={"allowed_wrapper_names": ["useMountEffect"]}))
    facts = Facts(project_path=".")

    valid = """
import { useEffect } from "react";
export function useMountEffect(effect) {
  useEffect(effect, []);
}
"""
    assert rule.analyze_ast("resources/js/hooks/useMountEffect.ts", valid, facts) == []

    near = """
import { useEffect } from "react";
export function useSocketSync() {
  useEffect(() => {
    const socket = new WebSocket("wss://example.test");
    return () => socket.close();
  }, []);
}
"""
    near_findings = NoDirectUseEffectRule(
        RuleConfig(thresholds={"suppress_external_sync": True})
    ).analyze_ast("resources/js/hooks/useSocketSync.ts", near, facts)
    assert near_findings == []

    invalid = """
import { useEffect, useState } from "react";
export function ProductPage({ productId }) {
  const [product, setProduct] = useState(null);
  useEffect(() => {
    fetch(`/api/products/${productId}`).then((r) => r.json()).then(setProduct);
  }, [productId]);
  return null;
}
"""
    findings = rule.analyze_ast("resources/js/pages/ProductPage.tsx", invalid, facts)
    assert len(findings) == 1


def test_useeffect_cleanup_missing_batch_r1_valid_near_invalid():
    rule = UseEffectCleanupMissingRule(
        RuleConfig(thresholds={"include_fetch_effects": False, "min_side_effect_signals": 1})
    )
    facts = Facts(project_path=".")

    valid = """
import { useEffect } from "react";
function Clock() {
  useEffect(() => {
    const timer = setInterval(() => {}, 1000);
    return () => clearInterval(timer);
  }, []);
  return null;
}
"""
    assert rule.analyze_regex("resources/js/components/Clock.tsx", valid, facts) == []

    near = """
import { useEffect } from "react";
function Profile() {
  useEffect(() => {
    fetch('/api/profile').then((r) => r.json());
  }, []);
  return null;
}
"""
    assert rule.analyze_regex("resources/js/components/Profile.tsx", near, facts) == []

    invalid = """
import { useEffect } from "react";
function Feed() {
  useEffect(() => {
    setInterval(() => console.log('tick'), 1000);
  }, []);
  return null;
}
"""
    findings = rule.analyze_regex("resources/js/components/Feed.tsx", invalid, facts)
    assert len(findings) == 1


def test_missing_usememo_for_expensive_calc_batch_r1_valid_near_invalid():
    rule = MissingUseMemoForExpensiveCalcRule(
        RuleConfig(
            thresholds={
                "min_complexity_score": 3,
                "min_chain_ops": 2,
                "require_assignment_or_return_context": True,
            }
        )
    )
    facts = Facts(project_path=".")

    valid = """
import { useMemo } from "react";
function List({ users, filter }) {
  const rows = useMemo(() => users.filter((u) => u.active).sort((a, b) => a.name.localeCompare(b.name)), [users, filter]);
  return <div>{rows.length}</div>;
}
"""
    assert rule.analyze_regex("resources/js/components/List.tsx", valid, facts) == []

    near = """
function MetaTags({ item }) {
  return (
    <div>
      {Object.entries(item.meta ?? {}).map(([k, v]) => <span key={k}>{v}</span>)}
    </div>
  );
}
"""
    assert rule.analyze_regex("resources/js/components/MetaTags.tsx", near, facts) == []

    invalid = """
function UserList({ users, filter }) {
  const totalScore = users.reduce((sum, user) => sum + user.score, 0);
  return <div>{filter}: {totalScore}</div>;
}
"""
    findings = rule.analyze_regex("resources/js/components/UserList.tsx", invalid, facts)
    assert len(findings) == 1


def test_missing_usecallback_for_event_handlers_batch_r1_valid_near_invalid():
    rule = MissingUseCallbackForEventHandlersRule(
        RuleConfig(
            thresholds={
                "require_memoized_child_context": True,
                "require_nontrivial_handler": True,
                "min_handler_complexity_score": 2,
            }
        )
    )
    facts = Facts(project_path=".")

    valid = """
function Button() {
  return <button onClick={() => setOpen(true)}>Open</button>;
}
"""
    assert rule.analyze_regex("resources/js/components/Button.tsx", valid, facts) == []

    near = """
function Card({ onSelect, item }) {
  return <Panel onSelect={() => onSelect(item.id)} />;
}
"""
    assert rule.analyze_regex("resources/js/components/Card.tsx", near, facts) == []

    invalid = """
import { memo } from 'react';
const ItemRow = memo(function ItemRow({ onSelect }) { return <button onClick={onSelect}>Open</button>; });
function List({ items, onSelect }) {
  return <div>{items.map((item) => <ItemRow key={item.id} onSelect={() => onSelect(item.id)} />)}</div>;
}
"""
    findings = rule.analyze_regex("resources/js/components/List.tsx", invalid, facts)
    assert len(findings) == 1


def test_batch_r1_context_matrix_entries_are_active():
    matrix = ContextProfileMatrix.load_default()
    default_ctx = matrix.resolve_context()
    realtime_ctx = matrix.resolve_context(
        explicit_profile="layered",
        explicit_project_type="realtime_game_control_platform",
        explicit_capabilities={"realtime": True, "mixed_public_dashboard": True},
    )
    api_ctx = matrix.resolve_context(explicit_profile="api-first", explicit_project_type="api_backend")

    for rule_id in BATCH_R1_RULES:
        calibrated = matrix.calibrate_rule(rule_id, default_ctx)
        assert isinstance(calibrated.get("thresholds"), dict)
        assert calibrated.get("severity") is not None

    assert matrix.calibrate_rule("large-react-component", realtime_ctx)["severity"] == "low"
    assert matrix.calibrate_rule("inline-api-logic", api_ctx)["severity"] in {"medium", "high"}


def test_batch_r1_rules_validate_across_mixed_react_fixtures(fixture_path: Path):
    fixtures = {
        "intentional_colocation": "react-intentional-colocation-mini",
        "hybrid_near_miss": "react-hybrid-near-miss-mini",
        "composed_alt_layout": "react-composed-page-alt-layout-mini",
        "inertia_react": "laravel-inertia-react-mini",
        "portal_style": "imposter-inertia-architecture-mini",
    }

    engine = create_engine(ruleset=_ruleset_for(BATCH_R1_RULES), selected_rules=BATCH_R1_RULES)
    for _, fixture_name in fixtures.items():
        root = fixture_path / fixture_name
        info = ProjectDetector(str(root)).detect()
        facts = FactsBuilder(info).build()
        metrics = MetricsAnalyzer().analyze(facts)
        result = engine.run(facts, metrics=metrics, project_type=info.project_type.value)
        assert isinstance(result.findings, list)
        assert facts.project_context.react_structure_mode in {"feature-first", "category-based", "hybrid", "unknown"}
