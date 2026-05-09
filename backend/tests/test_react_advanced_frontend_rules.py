from __future__ import annotations

from schemas.facts import Facts
from rules.react.advanced_frontend_props import (
    InlinePropObjectArrayRule,
    LooseDefaultObjectPropRule,
    UnstableReactKeyRule,
)
from rules.react.missing_empty_state import MissingEmptyStateRule
from rules.react.missing_loading_state import MissingLoadingStateRule
from rules.react.use_memo_overuse import UseMemoOveruseRule


def _facts() -> Facts:
    return Facts(project_path=".")


def test_inline_prop_object_array_detects_custom_component_array_prop():
    rule = InlinePropObjectArrayRule()
    invalid = "export function Page(){ return <Chart items={[1, 2, 3]} />; }"
    valid_native = "export function Box(){ return <div style={{ color: 'red' }} />; }"
    valid_allowed_prop = "export function Box(){ return <Chart style={{ color: 'red' }} />; }"

    assert len(rule.analyze_regex("src/components/Chart.tsx", invalid, _facts())) == 1
    assert rule.analyze_regex("src/components/Box.tsx", valid_native, _facts()) == []
    assert rule.analyze_regex("src/components/Box.tsx", valid_allowed_prop, _facts()) == []


def test_inline_prop_object_array_detects_custom_component_object_prop():
    rule = InlinePropObjectArrayRule()
    invalid = "export function Page(){ return <Chart config={{ compact: true }} />; }"

    findings = rule.analyze_regex("src/components/Chart.tsx", invalid, _facts())

    assert len(findings) == 1
    assert findings[0].rule_id == "inline-prop-object-array"


def test_unstable_react_key_detects_template_literal_and_call_expression():
    rule = UnstableReactKeyRule()
    template_key = "items.map(label => <Row key={`kpi-${label}`} label={label} />)"
    call_key = "items.map(item => <Row key={t('name')} item={item} />)"
    stable_key = "items.map(item => <Row key={item.id} item={item} />)"

    assert len(rule.analyze_regex("src/components/List.tsx", template_key, _facts())) == 1
    assert len(rule.analyze_regex("src/components/List.tsx", call_key, _facts())) == 1
    assert rule.analyze_regex("src/components/List.tsx", stable_key, _facts()) == []


def test_unstable_react_key_detects_weak_identifier_but_allows_id_identifier():
    rule = UnstableReactKeyRule()
    weak = "items.map(label => <Row key={label} label={label} />)"
    stable = "items.map(id => <Row key={id} id={id} />)"

    assert len(rule.analyze_regex("src/components/List.tsx", weak, _facts())) == 1
    assert rule.analyze_regex("src/components/List.tsx", stable, _facts()) == []


def test_unstable_react_key_allows_static_literal_array_values():
    rule = UnstableReactKeyRule()
    inline_static = '["all", "draft", "sent"].map(s => <Tab key={s} value={s} />)'
    const_static = "const statusOrder = ['draft', 'sent']; statusOrder.map(status => <Tab key={status} />)"

    assert rule.analyze_regex("src/components/Tabs.tsx", inline_static, _facts()) == []
    assert rule.analyze_regex("src/components/Tabs.tsx", const_static, _facts()) == []


def test_unstable_react_key_allows_stable_composite_keys():
    rule = UnstableReactKeyRule()
    stable_schedule = "slots.map(s => <Row key={`${day}-${s.start}-${s.end}`} />)"
    stable_prefix = "checks.map(check => <Row key={`check-${check.name}`} />)"

    assert rule.analyze_regex("src/components/Schedule.tsx", stable_schedule, _facts()) == []
    assert rule.analyze_regex("src/components/Checks.tsx", stable_prefix, _facts()) == []


def test_unstable_react_key_allows_hook_generated_key_alias():
    rule = UnstableReactKeyRule()
    valid = """
const rowKeys = useLoadingRowKeys(rows.length);
return rowKeys.map(rowKey => <tr key={rowKey} />);
"""

    assert rule.analyze_regex("src/components/SkeletonTable.tsx", valid, _facts()) == []


def test_unstable_react_key_allows_reviewed_static_and_deduped_filter_keys():
    rule = UnstableReactKeyRule()
    static_weekdays = """
const DAYS = ["mon", "tue", "wed", "thu", "fri"];
return DAYS.map((day) => <div key={`schedule-day-${day}`} />);
"""
    static_tuple = """
return (["all", "ok", "low"] as const).map((s) => <button key={`inventory-status-filter-${s}`} />);
"""
    deduped_statuses = """
const statuses = Array.from(new Set(claims.map((c) => c.status)));
return ["all", ...statuses].map((s) => <button key={`claim-status-filter-${s}`} />);
"""
    deduped_categories = """
const categories = Array.from(new Set(items.map((i) => i.category).filter(Boolean)));
return categories.map((c) => <option key={`inventory-category-${c}`} value={c} />);
"""

    assert rule.analyze_regex("src/pages/Schedule.tsx", static_weekdays, _facts()) == []
    assert rule.analyze_regex("src/pages/Inventory.tsx", static_tuple, _facts()) == []
    assert rule.analyze_regex("src/pages/Claims.tsx", deduped_statuses, _facts()) == []
    assert rule.analyze_regex("src/pages/Inventory.tsx", deduped_categories, _facts()) == []


def test_unstable_react_key_allows_row_key_helper_and_single_remount_key():
    rule = UnstableReactKeyRule()
    table_helper = """
const getRowKey = (row) => rowKey?.(row) ?? row.id ?? row.public_id ?? JSON.stringify(row);
return rows.map((row) => <tr key={getRowKey(row)} />);
"""
    single_avatar_remount = """
return userAvatarUrl ? <img key={`avatar-image-${userAvatarUrl}`} src={userAvatarUrl} /> : null;
"""

    assert rule.analyze_regex("src/components/UI/Table.tsx", table_helper, _facts()) == []
    assert rule.analyze_regex("src/layouts/AuthenticatedLayoutSidebarContent.tsx", single_avatar_remount, _facts()) == []


def test_unstable_react_key_allows_scoped_deterministic_feature_value_key():
    rule = UnstableReactKeyRule()
    valid = """
return plans.map((plan) => (
  <Card key={plan.id}>
    {(plan.features ?? []).slice(0, 4).map((feature, featureIndex) => (
      <Badge key={`${plan.id}-feature-${featureIndex}-${String(feature)}`} />
    ))}
  </Card>
));
"""

    assert rule.analyze_regex("src/pages/Portal/Subscriptions/Index.tsx", valid, _facts()) == []


def test_unstable_react_key_still_flags_dynamic_and_translation_keys():
    rule = UnstableReactKeyRule()
    random_key = "items.map((item) => <Row key={`row-${Math.random()}`} />)"
    translated_key = "items.map((item) => <Row key={`row-${t(item.name)}`} />)"

    assert len(rule.analyze_regex("src/components/List.tsx", random_key, _facts())) == 1
    assert len(rule.analyze_regex("src/components/List.tsx", translated_key, _facts())) == 1


def test_missing_loading_state_detects_async_page_without_loading_branch():
    rule = MissingLoadingStateRule({})
    invalid = """
export function UsersPage() {
  const { data } = useQuery(["users"], fetchUsers);
  return <>{data.items.map(item => <div>{item.name}</div>)}</>;
}
"""
    valid = """
export function UsersPage() {
  const { data, isLoading } = useQuery(["users"], fetchUsers);
  if (isLoading) return <Loading />;
  return <>{data.items.map(item => <div>{item.name}</div>)}</>;
}
"""

    assert len(rule.analyze_ast("src/pages/Users.tsx", invalid, _facts())) == 1
    assert rule.analyze_ast("src/pages/Users.tsx", valid, _facts()) == []


def test_missing_empty_state_detects_page_list_without_empty_branch():
    rule = MissingEmptyStateRule({})
    invalid = "export function UsersPage({ items }) { return <>{items.map(item => <div>{item.name}</div>)}</>; }"
    valid = "export function UsersPage({ items }) { return items.length === 0 ? <Empty /> : <>{items.map(item => <div>{item.name}</div>)}</>; }"
    fp_guard = "export function UsersPage() { const items = [1, 2, 3]; return <>{items.map(item => <div>{item}</div>)}</>; }"

    assert len(rule.analyze_ast("src/pages/Users.tsx", invalid, _facts())) == 1
    assert rule.analyze_ast("src/pages/Users.tsx", valid, _facts()) == []
    assert rule.analyze_ast("src/pages/Users.tsx", fp_guard, _facts()) == []


def test_loose_default_object_prop_detects_component_prop_default():
    rule = LooseDefaultObjectPropRule()
    invalid = "function Panel({ data = {} }) { return <div>{data.name}</div>; }"
    valid = "function Panel({ data }) { return <div>{data.name}</div>; }"

    assert len(rule.analyze_regex("src/components/Panel.tsx", invalid, _facts())) == 1
    assert rule.analyze_regex("src/components/Panel.tsx", valid, _facts()) == []


def test_loose_default_object_prop_detects_arrow_component_and_skips_utility():
    rule = LooseDefaultObjectPropRule()
    invalid = "const Panel = ({ data = {} }) => <div>{data.name}</div>;"
    fp_guard = "function normalize({ data = {} }) { return data; }"

    assert len(rule.analyze_regex("src/components/Panel.tsx", invalid, _facts())) == 1
    assert rule.analyze_regex("src/utils/normalize.ts", fp_guard, _facts()) == []


def test_usememo_overuse_allows_stripe_elements_options_object():
    rule = UseMemoOveruseRule({})
    valid = """
import { Elements } from '@stripe/react-stripe-js';
const stripeOptions = React.useMemo(() => ({ clientSecret }), [clientSecret]);
return <Elements options={stripeOptions} stripe={stripePromise} />;
"""

    assert rule.analyze_ast("src/pages/Auth/Onboarding/Steps/Payment/Show.tsx", valid, _facts()) == []


def test_usememo_overuse_still_flags_trivial_non_provider_expression():
    rule = UseMemoOveruseRule({})
    invalid = "const label = React.useMemo(() => name, [name]); return <div>{label}</div>;"

    assert len(rule.analyze_ast("src/components/Name.tsx", invalid, _facts())) == 1
