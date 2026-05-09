from __future__ import annotations

from core.context_profiles import ContextProfileMatrix
from core.ruleset import RuleConfig
from rules.react.cross_feature_import_boundary import CrossFeatureImportBoundaryRule
from rules.react.derived_state_in_effect import DerivedStateInEffectRule
from rules.react.effect_event_relay_smell import EffectEventRelaySmellRule
from rules.react.large_custom_hook import LargeCustomHookRule
from rules.react.query_key_instability import QueryKeyInstabilityRule
from rules.react.route_shell_missing_error_boundary import RouteShellMissingErrorBoundaryRule
from rules.react.state_update_in_render import StateUpdateInRenderRule
from rules.react.unsafe_async_handler_without_guard import UnsafeAsyncHandlerWithoutGuardRule
from schemas.facts import Facts


def test_r2_matrix_entries_exist():
    matrix = ContextProfileMatrix.load_default()
    for rule_id in {
        "derived-state-in-effect",
        "state-update-in-render",
        "large-custom-hook",
        "cross-feature-import-boundary",
        "query-key-instability",
        "effect-event-relay-smell",
        "route-shell-missing-error-boundary",
        "unsafe-async-handler-without-guard",
    }:
        assert rule_id in matrix.rule_behavior


def test_derived_state_in_effect_valid_near_invalid():
    rule = DerivedStateInEffectRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = """
function SocketView() {
  useEffect(() => {
    const ws = new WebSocket('wss://example');
    return () => ws.close();
  }, []);
}
"""
    assert rule.analyze_regex("resources/js/pages/SocketView.tsx", valid, facts) == []

    near = """
function Modal() {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    setOpen(true);
  }, []);
}
"""
    assert rule.analyze_regex("resources/js/pages/Modal.tsx", near, facts) == []

    invalid = """
function Users({ users, term }) {
  const [filtered, setFiltered] = useState([]);
  useEffect(() => {
    setFiltered(users.filter((u) => u.name.includes(term)));
  }, [users, term]);
}
"""
    findings = rule.analyze_regex("resources/js/pages/Users.tsx", invalid, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "derived-state-in-effect"


def test_state_update_in_render_valid_near_invalid():
    rule = StateUpdateInRenderRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = """
function Counter() {
  const [count, setCount] = useState(0);
  return <button onClick={() => setCount((c) => c + 1)}>Add</button>;
}
"""
    assert rule.analyze_ast("resources/js/pages/Counter.tsx", valid, facts) == []

    near = """
function Counter() {
  const [count, setCount] = useState(0);
  useEffect(() => {
    setCount(1);
  }, []);
  return <div>{count}</div>;
}
"""
    assert rule.analyze_ast("resources/js/pages/Counter.tsx", near, facts) == []

    invalid = """
function Counter() {
  const [count, setCount] = useState(0);
  setCount(count + 1);
  return <div>{count}</div>;
}
"""
    findings = rule.analyze_ast("resources/js/pages/Counter.tsx", invalid, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "state-update-in-render"


def test_large_custom_hook_valid_near_invalid():
    rule = LargeCustomHookRule(RuleConfig(thresholds={"max_loc": 50, "min_overflow_lines": 10, "min_logic_signals": 3}))
    facts = Facts(project_path=".")

    valid = """
export function useSmallHook() {
  const [value, setValue] = useState(0);
  return { value, setValue };
}
"""
    assert rule.analyze_regex("resources/js/hooks/useSmallHook.ts", valid, facts) == []

    near = "\n".join([f"const line{i} = {i};" for i in range(80)])
    assert rule.analyze_regex("resources/js/hooks/useBigButSimpleHook.ts", near, facts) == []

    invalid = "\n".join(
        ["export function useBigHook() {"]
        + ["  const [a, setA] = useState(0);", "  useEffect(() => {}, []);", "  const b = useMemo(() => a + 1, [a]);"]
        + [f"  const v{i} = fetch('/api/{i}');" for i in range(150)]
        + ["  return { a, b };", "}"]
    )
    findings = rule.analyze_regex("resources/js/hooks/useBigHook.ts", invalid, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "large-custom-hook"


def test_cross_feature_import_boundary_valid_near_invalid():
    rule = CrossFeatureImportBoundaryRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = "import { getUser } from '@/features/users';\n"
    assert rule.analyze_regex("src/features/dashboard/widgets/Chart.tsx", valid, facts) == []

    near = "import { useFilter } from '@/features/dashboard/internal/useFilter';\n"
    assert rule.analyze_regex("src/features/dashboard/pages/Home.tsx", near, facts) == []

    invalid = "import { useUserInternal } from '@/features/users/internal/useUserInternal';\n"
    findings = rule.analyze_regex("src/features/dashboard/pages/Home.tsx", invalid, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "cross-feature-import-boundary"


def test_query_key_instability_valid_near_invalid():
    rule = QueryKeyInstabilityRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = """
const query = useQuery({
  queryKey: ['users', clinicId, status],
  queryFn: fetchUsers,
});
"""
    assert rule.analyze_regex("resources/js/pages/Users.tsx", valid, facts) == []

    near = """
const query = useQuery({
  queryKey: ['users', params],
  queryFn: fetchUsers,
});
"""
    assert rule.analyze_regex("resources/js/pages/Users.tsx", near, facts) == []

    invalid = """
const query = useQuery({
  queryKey: ['users', { clinicId, status }],
  queryFn: fetchUsers,
});
"""
    findings = rule.analyze_regex("resources/js/pages/Users.tsx", invalid, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "query-key-instability"


def test_effect_event_relay_smell_valid_near_invalid():
    rule = EffectEventRelaySmellRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = """
function SaveButton() {
  const handleSave = async () => {
    await submit();
  };
}
"""
    assert rule.analyze_regex("resources/js/pages/SaveButton.tsx", valid, facts) == []

    near = """
function SaveButton() {
  const [submitRequested, setSubmitRequested] = useState(false);
  useEffect(() => {
    if (submitRequested) {
      submit();
    }
  }, [submitRequested]);
}
"""
    assert rule.analyze_regex("resources/js/pages/SaveButton.tsx", near, facts) == []

    invalid = """
function SaveButton() {
  const [submitRequested, setSubmitRequested] = useState(false);
  const onClick = () => setSubmitRequested(true);
  useEffect(() => {
    if (submitRequested) {
      submitOrder();
      setSubmitRequested(false);
    }
  }, [submitRequested]);
}
"""
    findings = rule.analyze_regex("resources/js/pages/SaveButton.tsx", invalid, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "effect-event-relay-smell"


def test_route_shell_missing_error_boundary_valid_near_invalid():
    rule = RouteShellMissingErrorBoundaryRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = """
export default function Dashboard() {
  const users = useQuery(['users'], fetchUsers);
  return <ErrorBoundary><UsersPanel data={users.data} /></ErrorBoundary>;
}
"""
    assert rule.analyze_regex("resources/js/pages/Admin/Dashboard.tsx", valid, facts) == []

    near = """
export default function Dashboard() {
  const users = useQuery(['users'], fetchUsers);
  return <UsersPanel data={users.data} />;
}
"""
    assert rule.analyze_regex("resources/js/components/Admin/DashboardWidget.tsx", near, facts) == []

    invalid = """
export default function Dashboard() {
  const users = useQuery(['users'], fetchUsers);
  const invoices = axios.get('/api/invoices');
  return <UsersPanel data={users.data} />;
}
"""
    findings = rule.analyze_regex("resources/js/pages/Admin/Dashboard.tsx", invalid, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "route-shell-missing-error-boundary"


def test_unsafe_async_handler_without_guard_valid_near_invalid():
    rule = UnsafeAsyncHandlerWithoutGuardRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = """
function SaveForm() {
  const [processing, setProcessing] = useState(false);
  const handleSave = async () => {
    if (processing) return;
    setProcessing(true);
    try {
      await api.post('/save');
    } finally {
      setProcessing(false);
    }
  };
  return <button onClick={handleSave} disabled={processing}>Save</button>;
}
"""
    assert rule.analyze_regex("resources/js/pages/SaveForm.tsx", valid, facts) == []

    near = """
function SaveForm() {
  const handleOpen = async () => {
    await Promise.resolve();
  };
  return <button onClick={handleOpen}>Open</button>;
}
"""
    assert rule.analyze_regex("resources/js/pages/SaveForm.tsx", near, facts) == []

    invalid = """
function SaveForm() {
  const handleSave = async () => {
    await api.post('/save');
  };
  return <button onClick={handleSave}>Save</button>;
}
"""
    findings = rule.analyze_regex("resources/js/pages/SaveForm.tsx", invalid, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "unsafe-async-handler-without-guard"
