from __future__ import annotations

from core.ruleset import RuleConfig
from rules.react.advanced_frontend_props import UnstableReactKeyRule
from rules.react.css_tailwind_accessibility_rules import TailwindMotionReduceMissingRule
from rules.react.css_tailwind_best_practice_rules import (
    TailwindArbitraryRadiusShadowRule,
    TailwindArbitrarySpacingRule,
    TailwindArbitraryValueOveruseRule,
)
from rules.react.focus_lost_on_route_change import FocusLostOnRouteChangeRule
from rules.react.hardcoded_user_facing_strings import HardcodedUserFacingStringsRule
from rules.react.inline_logic import InlineLogicRule
from rules.react.missing_empty_state import MissingEmptyStateRule
from rules.react.missing_loading_state import MissingLoadingStateRule
from rules.react.no_direct_useeffect import NoDirectUseEffectRule
from rules.react.page_title_missing import PageTitleMissingRule
from rules.react.react_parent_child_spacing_overlap import ReactParentChildSpacingOverlapRule
from schemas.facts import Facts, ProjectContext, ReactComponentInfo


def _facts(*, i18n: bool = False) -> Facts:
    return Facts(
        project_path=".",
        npm_packages={"tailwindcss": "^4.0.0"},
        project_context=ProjectContext(has_i18n=i18n),
    )


def test_report_page_title_does_not_classify_colocated_data_module_as_page() -> None:
    rule = PageTitleMissingRule(RuleConfig())
    data_module = """
export const ADMIN_USER_COLUMNS = [
  { key: 'name', label: 'Name' },
  { key: 'email', label: 'Email' },
];
export const formatRole = (role: string) => role.toUpperCase();
"""
    rendered_page = "export default function AdminUsersPage() { return <main>Users</main>; }"

    assert rule.analyze_regex(
        "resources/js/pages/Lms/AdminUsers/AdminUsersPage.data.ts",
        data_module,
        _facts(),
    ) == []
    assert len(
        rule.analyze_regex(
            "features/admin/AdminUsersPage.tsx",
            rendered_page,
            _facts(),
        ),
    ) == 1


def test_report_navigation_triggers_do_not_claim_route_lifecycle_ownership() -> None:
    rule = FocusLostOnRouteChangeRule()
    triggers = [
        '<Link href="/admin">Admin</Link>',
        "router.visit('/admin')",
        '<nav><Link href="/404">Try again</Link></nav>',
    ]
    for content in triggers:
        assert rule.analyze_regex("src/AnyComponent.tsx", content, _facts()) == []

    lifecycle_owner = "router.on('finish', () => announcePage());"
    assert len(rule.analyze_regex("src/AppShell.tsx", lifecycle_owner, _facts())) == 1


def test_report_key_examples_distinguish_determinism_from_runtime_instability() -> None:
    rule = UnstableReactKeyRule()
    deterministic = "teams.map(teamNum => <Input key={`team-number-${teamNum}`} />)"
    positional = "Array.from({ length: rows }).map((_, i) => <Skeleton key={i} />)"
    dynamic_index = "scores.map((score, i) => <ScoreRow key={i} score={score} />)"
    random = "scores.map(score => <ScoreRow key={Math.random()} score={score} />)"

    assert rule.analyze_regex("src/GameSetupPanel.tsx", deterministic, _facts()) == []
    assert rule.analyze_regex("src/Skeleton.tsx", positional, _facts()) == []
    assert len(rule.analyze_regex("src/Scoreboard.tsx", dynamic_index, _facts())) == 1
    assert len(rule.analyze_regex("src/Scoreboard.tsx", random, _facts())) == 1


def test_report_custom_hooks_are_valid_effect_boundaries() -> None:
    rule = NoDirectUseEffectRule(RuleConfig())
    hook = """
export function useLmsStateSync(channel) {
  useEffect(() => {
    channel.subscribe();
    return () => channel.unsubscribe();
  }, [channel]);
}
export const useSubscriptionEffect = (subscribe) => {
  useEffect(() => subscribe(), [subscribe]);
};
"""
    component = "export function Panel() { useEffect(() => setOpen(false), [id]); return null; }"

    assert rule.analyze_ast("src/hooks/useLmsStateSync.ts", hook, _facts()) == []
    assert len(rule.analyze_ast("src/Panel.tsx", component, _facts())) == 1


def test_report_hook_count_alone_is_not_complex_inline_state(tmp_path) -> None:
    source = """import { useState } from 'react';
export function AdminGameShell() {
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState('board');
  const [selected, setSelected] = useState(null);
  return <GameBoard open={open} tab={tab} selected={selected} />;
}
"""
    path = tmp_path / "features" / "AdminGameShell.tsx"
    path.parent.mkdir(parents=True)
    path.write_text(source, encoding="utf-8")
    component = ReactComponentInfo(
        name="AdminGameShell",
        file_path="features/AdminGameShell.tsx",
        file_hash="fixture",
        line_start=1,
        line_end=8,
        loc=8,
        hooks_used=["useState", "useState", "useState"],
        has_inline_state_logic=True,
    )
    facts = Facts(project_path=str(tmp_path), react_components=[component])

    assert InlineLogicRule(RuleConfig(thresholds={"min_state_hook_count": 3})).analyze(facts) == []


def test_report_tailwind_design_exceptions_do_not_create_policy_spam() -> None:
    shadows = """
const first = cva('shadow-[0_0_22px_var(--tw-shadow-color)]');
const second = cva('focus-within:shadow-[0_0_0_3px_rgb(from_var(--color-lms-purple-light)_r_g_b_/_0.12)]');
"""
    overlay = (
        '<aside className="z-[1000] w-[360px] max-w-[calc(100vw-2rem)] '
        'bg-[linear-gradient(180deg,rgb(from_var(--panel)_r_g_b),rgb(from_var(--bg)_r_g_b))] '
        'transition-transform" />'
    )
    actual_motion = '<div className="animate-spin" />'

    assert TailwindArbitraryRadiusShadowRule(RuleConfig()).analyze_regex("src/Card.tsx", shadows, _facts()) == []
    assert TailwindArbitraryValueOveruseRule(RuleConfig()).analyze_regex("src/Overlay.tsx", overlay, _facts()) == []
    assert TailwindMotionReduceMissingRule(RuleConfig()).analyze_regex("src/Overlay.tsx", overlay, _facts()) == []
    assert len(
        TailwindMotionReduceMissingRule(RuleConfig()).analyze_regex("src/Spinner.tsx", actual_motion, _facts()),
    ) == 1


def test_report_loading_rule_requires_a_page_owned_query_contract() -> None:
    rule = MissingLoadingStateRule(RuleConfig())
    inertia_refresh = "export function Board() { const refresh = () => router.reload(); return <BoardRows />; }"
    query_page = "export function Board() { const { data } = useQuery(['board'], loadBoard); return <BoardRows rows={data} />; }"

    assert rule.analyze_ast("src/pages/Board.tsx", inertia_refresh, _facts()) == []
    assert len(rule.analyze_ast("src/pages/Board.tsx", query_page, _facts())) == 1


def test_report_policy_rules_remain_available_only_with_real_evidence_or_opt_in() -> None:
    overlap = "export function ErrorPage() { return <main className='px-6'><div className='px-6'>Denied</div></main>; }"
    dynamic_list = "export function Leaders({ leaders }) { return <>{leaders.map(x => <div key={x.id}>{x.name}</div>)}</>; }"
    translated_spacing = "<div className='gap-[6px] px-[10px]' />"
    hardcoded = """export function Link() {
  return <a>Go to Admin Panel</a>;
}"""

    assert ReactParentChildSpacingOverlapRule(RuleConfig()).analyze_ast("src/pages/Error.tsx", overlap, _facts()) == []
    assert len(MissingEmptyStateRule(RuleConfig()).analyze_ast("src/pages/Leaders.tsx", dynamic_list, _facts())) == 1
    assert len(
        TailwindArbitrarySpacingRule(RuleConfig()).analyze_regex("src/AdminUsers.tsx", translated_spacing, _facts()),
    ) == 1
    assert len(
        HardcodedUserFacingStringsRule(RuleConfig()).analyze_regex("src/PlayerStage.tsx", hardcoded, _facts(i18n=True)),
    ) == 1
