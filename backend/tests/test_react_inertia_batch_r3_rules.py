from __future__ import annotations

from core.rule_engine import ALL_RULES
from core.ruleset import RuleConfig
from rules.laravel.inertia_shared_props_payload_budget import InertiaSharedPropsPayloadBudgetRule
from rules.react.inertia_reload_without_only import InertiaReloadWithoutOnlyRule
from rules.react.react_event_listener_cleanup_required import ReactEventListenerCleanupRequiredRule
from rules.react.react_no_props_mutation import ReactNoPropsMutationRule
from rules.react.react_no_random_key import ReactNoRandomKeyRule
from rules.react.react_no_state_mutation import ReactNoStateMutationRule
from rules.react.react_side_effects_in_render import ReactSideEffectsInRenderRule
from rules.react.react_timer_cleanup_required import ReactTimerCleanupRequiredRule
from schemas.facts import Facts


def test_r3_rules_registered():
    for rule_id in {
        "react-no-random-key",
        "react-no-props-mutation",
        "react-no-state-mutation",
        "react-side-effects-in-render",
        "react-event-listener-cleanup-required",
        "react-timer-cleanup-required",
        "inertia-shared-props-payload-budget",
        "inertia-reload-without-only",
    }:
        assert rule_id in ALL_RULES


def test_react_no_random_key_valid_near_invalid():
    rule = ReactNoRandomKeyRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = """
{users.map((user) => <li key={user.id}>{user.name}</li>)}
"""
    assert rule.analyze_regex("resources/js/pages/Users.tsx", valid, facts) == []

    near = """
{users.map((user, index) => <li key={`${user.id}-${index}`}>{user.name}</li>)}
"""
    assert rule.analyze_regex("resources/js/pages/Users.tsx", near, facts) == []

    invalid = """
{users.map((user) => <li key={Math.random()}>{user.name}</li>)}
"""
    findings = rule.analyze_regex("resources/js/pages/Users.tsx", invalid, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "react-no-random-key"


def test_react_no_props_mutation_valid_near_invalid():
    rule = ReactNoPropsMutationRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = """
export default function Card(props) {
  return <div>{props.title}</div>;
}
"""
    assert rule.analyze_regex("resources/js/components/Card.tsx", valid, facts) == []

    near = """
const propsMap = {};
propsMap.title = "x";
"""
    assert rule.analyze_regex("resources/js/components/Card.tsx", near, facts) == []

    invalid = """
export default function Card(props) {
  props.user.name = "edited";
  return <div>{props.user.name}</div>;
}
"""
    findings = rule.analyze_regex("resources/js/components/Card.tsx", invalid, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "react-no-props-mutation"


def test_react_no_state_mutation_valid_near_invalid():
    rule = ReactNoStateMutationRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = """
function List() {
  const [items, setItems] = useState([]);
  const add = (item) => setItems((prev) => [...prev, item]);
  return <button onClick={() => add('x')}>Add</button>;
}
"""
    assert rule.analyze_regex("resources/js/components/List.tsx", valid, facts) == []

    near = """
function List() {
  const [items, setItems] = useState([]);
  const local = [];
  local.push('x');
  return <div>{items.length === 0 ? 'None' : 'Some'}</div>;
}
"""
    assert rule.analyze_regex("resources/js/components/List.tsx", near, facts) == []

    invalid = """
function List() {
  const [items, setItems] = useState([]);
  items.push('x');
  return <div>{items.length}</div>;
}
"""
    findings = rule.analyze_regex("resources/js/components/List.tsx", invalid, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "react-no-state-mutation"


def test_react_side_effects_in_render_valid_near_invalid():
    rule = ReactSideEffectsInRenderRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = """
export default function Dashboard() {
  const handleRefresh = () => {
    router.reload();
  };
  return <button onClick={handleRefresh}>Refresh</button>;
}
"""
    assert rule.analyze_ast("resources/js/pages/Admin/Dashboard.tsx", valid, facts) == []

    near = """
export default function Dashboard() {
  const { data } = useQuery({ queryKey: ['users'], queryFn: fetchUsers });
  return <div>{data?.length}</div>;
}
"""
    assert rule.analyze_ast("resources/js/pages/Admin/Dashboard.tsx", near, facts) == []

    invalid = """
export default function Dashboard() {
  router.reload();
  return <div>Dashboard</div>;
}
"""
    findings = rule.analyze_ast("resources/js/pages/Admin/Dashboard.tsx", invalid, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "react-side-effects-in-render"


def test_react_event_listener_cleanup_required_valid_near_invalid():
    rule = ReactEventListenerCleanupRequiredRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = """
useEffect(() => {
  const onResize = () => {};
  window.addEventListener('resize', onResize);
  return () => window.removeEventListener('resize', onResize);
}, []);
"""
    assert rule.analyze_regex("resources/js/hooks/useResize.ts", valid, facts) == []

    near = """
const bind = () => window.addEventListener('resize', () => {});
"""
    assert rule.analyze_regex("resources/js/hooks/useResize.ts", near, facts) == []

    invalid = """
useEffect(() => {
  const onResize = () => {};
  window.addEventListener('resize', onResize);
}, []);
"""
    findings = rule.analyze_regex("resources/js/hooks/useResize.ts", invalid, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "react-event-listener-cleanup-required"


def test_react_timer_cleanup_required_valid_near_invalid():
    rule = ReactTimerCleanupRequiredRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = """
useEffect(() => {
  const id = setInterval(tick, 1000);
  return () => clearInterval(id);
}, []);
"""
    assert rule.analyze_regex("resources/js/hooks/useTicker.ts", valid, facts) == []

    near = """
const onClick = () => {
  setTimeout(() => doSomething(), 1000);
};
"""
    assert rule.analyze_regex("resources/js/hooks/useTicker.ts", near, facts) == []

    invalid = """
useEffect(() => {
  const id = setInterval(tick, 1000);
}, []);
"""
    findings = rule.analyze_regex("resources/js/hooks/useTicker.ts", invalid, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "react-timer-cleanup-required"


def test_inertia_shared_props_payload_budget_valid_near_invalid():
    rule = InertiaSharedPropsPayloadBudgetRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = """
public function share(Request $request): array
{
    return array_merge(parent::share($request), [
        'recentOrders' => fn () => Order::query()->latest()->take(5)->get(),
        'ordersCount' => Order::query()->count(),
    ]);
}
"""
    assert (
        rule.analyze_regex(
            "app/Http/Middleware/HandleInertiaRequests.php",
            valid,
            facts,
        )
        == []
    )

    near = """
public function share(Request $request): array
{
    return array_merge(parent::share($request), [
        'ordersCount' => Order::query()->count(),
    ]);
}
"""
    assert (
        rule.analyze_regex(
            "app/Http/Middleware/HandleInertiaRequests.php",
            near,
            facts,
        )
        == []
    )

    invalid = """
public function share(Request $request): array
{
    return array_merge(parent::share($request), [
        'orders' => Order::query()->with('items')->get(),
    ]);
}
"""
    findings = rule.analyze_regex("app/Http/Middleware/HandleInertiaRequests.php", invalid, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "inertia-shared-props-payload-budget"


def test_inertia_reload_without_only_valid_near_invalid():
    rule = InertiaReloadWithoutOnlyRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = """
router.reload({ only: ['stats', 'filters'] });
"""
    assert rule.analyze_regex("resources/js/pages/Admin/Dashboard.tsx", valid, facts) == []

    near = """
const options = buildReloadOptions();
router.reload(options);
"""
    assert rule.analyze_regex("resources/js/pages/Admin/Dashboard.tsx", near, facts) == []

    invalid = """
router.reload({ preserveScroll: true });
"""
    findings = rule.analyze_regex("resources/js/pages/Admin/Dashboard.tsx", invalid, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "inertia-reload-without-only"
