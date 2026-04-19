from __future__ import annotations

from pathlib import Path

import pytest

from core.context_profiles import ContextProfileMatrix
from core.ruleset import RuleConfig, Ruleset
from rules.react.jsx_tree_sitter import JsxTreeSitterHelper
from rules.react.react_gap_expansion_rules import (
    AvoidPropsToStateCopyRule,
    PropsStateSyncEffectSmellRule,
    ControlledUncontrolledInputMismatchRule,
    UseMemoOveruseRule,
    UseCallbackOveruseRule,
    ContextOversizedProviderRule,
    LazyWithoutSuspenseRule,
    SuspenseFallbackMissingRule,
    StaleClosureInTimerRule,
    StaleClosureInListenerRule,
    DuplicateKeySourceRule,
    MissingLoadingStateRule,
    MissingEmptyStateRule,
    RefAccessDuringRenderRule,
    RefUsedAsReactiveStateRule,
)
from rules.react.react_seo_expansion_rules import (
    MetaDescriptionMissingOrGenericRule,
    CanonicalMissingOrInvalidRule,
    RobotsDirectiveRiskRule,
    CrawlableInternalNavigationRequiredRule,
    JsonLdStructuredDataInvalidOrMismatchedRule,
    H1SingletonViolationRule,
    PageIndexabilityConflictRule,
)
from schemas.facts import Facts, ProjectContext


AST_READY = JsxTreeSitterHelper().is_ready()


def _public_facts() -> Facts:
    return Facts(
        project_path=".",
        project_context=ProjectContext(
            project_type="public_website_with_dashboard",
            capabilities={
                "mixed_public_dashboard": {"enabled": True, "source": "explicit", "confidence": 0.9},
                "public_marketing_site": {"enabled": True, "source": "explicit", "confidence": 0.9},
            },
        ),
    )


GAP_CASES = [
    (
        "avoid-props-to-state-copy",
        AvoidPropsToStateCopyRule,
        "resources/js/Pages/Profile/Edit.tsx",
        "export function Edit({ value }) { return <div>{value}</div>; }",
        "export function Edit({ value }) { const [v, setV] = useState(() => value); return <div>{v}</div>; }",
        "export function Edit(props) { const [value, setValue] = useState(props.value); return <div>{value}</div>; }",
    ),
    (
        "props-state-sync-effect-smell",
        PropsStateSyncEffectSmellRule,
        "resources/js/Pages/Profile/Edit.tsx",
        "export function Edit({ value }) { useEffect(() => { fetch('/x'); }, [value]); return null; }",
        "export function Edit({ value }) { useEffect(() => { setRows(items.map(i => i.id)); }, [items]); return null; }",
        "export function Edit({ value }) { const [local, setLocal] = useState(''); useEffect(() => { setLocal(value); }, [value]); return null; }",
    ),
    (
        "controlled-uncontrolled-input-mismatch",
        ControlledUncontrolledInputMismatchRule,
        "resources/js/Pages/Profile/Edit.tsx",
        "export function Edit({ name, setName }) { return <input value={name} onChange={(e) => setName(e.target.value)} />; }",
        "export function Edit() { return <input defaultValue='John' />; }",
        "export function Edit({ name }) { return <input value={name} defaultValue='John' />; }",
    ),
    (
        "usememo-overuse",
        UseMemoOveruseRule,
        "resources/js/Pages/Admin/Dashboard.tsx",
        "export function Dashboard({ rows }) { const items = useMemo(() => rows.map(r => r.id), [rows]); return <div>{items.length}</div>; }",
        "export function Dashboard({ a, b, c }) { const x = useMemo(() => a + b + c, [a, b, c]); return <div>{x}</div>; }",
        "export function Dashboard({ flag }) { const label = useMemo(() => (flag ? 'ON' : 'OFF'), [flag]); return <div>{label}</div>; }",
    ),
    (
        "usecallback-overuse",
        UseCallbackOveruseRule,
        "resources/js/Pages/Admin/Dashboard.tsx",
        "export function Dashboard() { const save = useCallback(async () => { await fetch('/api/save'); }, []); return <button onClick={save}>Save</button>; }",
        "export function Dashboard({ a, b }) { const onGo = useCallback(() => run(a, b), [a, b]); return <button onClick={onGo}>Go</button>; }",
        "export function Dashboard() { const onOpen = useCallback(() => setOpen(true), []); return <button onClick={onOpen}>Open</button>; }",
    ),
    (
        "context-oversized-provider",
        ContextOversizedProviderRule,
        "resources/js/Pages/Admin/Dashboard.tsx",
        "export function App(){ return <AppContext.Provider value={{a:1,b:2,c:3}}><main /></AppContext.Provider>; }",
        "export function App(){ return <AppContext.Provider value={{a:1,b:2,c:3,d:4,e:5}}><main /></AppContext.Provider>; }",
        "export function App(){ return <AppContext.Provider value={{a:1,b:2,c:3,d:4,e:5,f:6,g:7}}><main /></AppContext.Provider>; }",
    ),
    (
        "lazy-without-suspense",
        LazyWithoutSuspenseRule,
        "resources/js/Pages/Admin/Dashboard.tsx",
        "const ReportsPage = React.lazy(() => import('./Reports')); export function App(){ return <Suspense fallback={<div/>}><ReportsPage/></Suspense>; }",
        "const ReportsPage = React.lazy(() => import('./Reports')); export function App(){ return <div>App</div>; }",
        "const ReportsPage = React.lazy(() => import('./Reports')); export function App(){ return <ReportsPage/>; }",
    ),
    (
        "suspense-fallback-missing",
        SuspenseFallbackMissingRule,
        "resources/js/Pages/Admin/Dashboard.tsx",
        "export function App(){ return <Suspense fallback={<div>Loading</div>}><Panel/></Suspense>; }",
        "export function App(){ return <div>App</div>; }",
        "export function App(){ return <Suspense><Panel/></Suspense>; }",
    ),
    (
        "stale-closure-in-timer",
        StaleClosureInTimerRule,
        "resources/js/Pages/Admin/Dashboard.tsx",
        "export function App(){ const [count,setCount]=useState(0); useEffect(() => { setInterval(() => console.log(count), 1000); }, [count]); return null; }",
        "export function App(){ const countRef=useRef(0); useEffect(() => { setInterval(() => console.log(countRef.current), 1000); }, []); return null; }",
        "export function App(){ const [count,setCount]=useState(0); useEffect(() => { setInterval(() => console.log(count), 1000); }, []); return null; }",
    ),
    (
        "stale-closure-in-listener",
        StaleClosureInListenerRule,
        "resources/js/Pages/Admin/Dashboard.tsx",
        "export function App(){ const [count,setCount]=useState(0); useEffect(() => { document.addEventListener('scroll', () => console.log(count)); }, [count]); return null; }",
        "export function App(){ const countRef=useRef(0); useEffect(() => { document.addEventListener('scroll', () => console.log(countRef.current)); }, []); return null; }",
        "export function App(){ const [count,setCount]=useState(0); useEffect(() => { document.addEventListener('scroll', () => console.log(count)); }, []); return null; }",
    ),
    (
        "duplicate-key-source",
        DuplicateKeySourceRule,
        "resources/js/Pages/Admin/Dashboard.tsx",
        "export function List({items}){ return <ul>{items.map((i) => <li key={i.id}>{i.name}</li>)}</ul>; }",
        "export function List({items}){ return <ul>{items.filter(Boolean).map((i) => <li>{i.name}</li>)}</ul>; }",
        "export function List({items}){ return <ul>{items.map((i) => <li key={i.name}>{i.name}</li>)}</ul>; }",
    ),
    (
        "missing-loading-state",
        MissingLoadingStateRule,
        "resources/js/Pages/Admin/Dashboard.tsx",
        "export default function Dashboard(){ const { data, isLoading } = useQuery(['a'], fetchA); if (isLoading) return <div>Loading</div>; return <div>{data?.length}</div>; }",
        "export default function Dashboard(){ return <div>Static page</div>; }",
        "export default function Dashboard(){ const { data } = useQuery(['a'], fetchA); return <div>{data?.length}</div>; }",
    ),
    (
        "missing-empty-state",
        MissingEmptyStateRule,
        "resources/js/Pages/Admin/Dashboard.tsx",
        "export default function Dashboard({items}){ if (items.length === 0) return <p>Empty</p>; return <ul>{items.map(i => <li key={i.id}>{i.name}</li>)}</ul>; }",
        "export default function Dashboard(){ return <div>No list</div>; }",
        "export default function Dashboard({items}){ return <ul>{items.map(i => <li key={i.id}>{i.name}</li>)}</ul>; }",
    ),
    (
        "ref-access-during-render",
        RefAccessDuringRenderRule,
        "resources/js/Pages/Admin/Dashboard.tsx",
        "export default function Dashboard(){ const nodeRef = useRef(null); useEffect(() => { console.log(nodeRef.current); }, []); return <div ref={nodeRef} />; }",
        "export default function Dashboard(){ const nodeRef = useRef(null); return <button>{nodeRef.current?.focus?.()}</button>; }",
        "export default function Dashboard(){ const nodeRef = useRef(null); return <div>{nodeRef.current}</div>; }",
    ),
    (
        "ref-used-as-reactive-state",
        RefUsedAsReactiveStateRule,
        "resources/js/Pages/Admin/Dashboard.tsx",
        "export default function Dashboard(){ const countRef = useRef(0); const [count,setCount]=useState(0); countRef.current = count; return <div>{count}</div>; }",
        "export default function Dashboard(){ const readyRef = useRef(false); readyRef.current = true; return <div>Done</div>; }",
        "export default function Dashboard(){ const readyRef = useRef(false); readyRef.current = true; return <div>{readyRef.current ? 'ready' : 'pending'}</div>; }",
    ),
]


@pytest.mark.parametrize("rule_id,rule_cls,file_path,valid,near,invalid", GAP_CASES)
def test_react_gap_rules_valid_near_invalid(rule_id, rule_cls, file_path, valid, near, invalid):
    if rule_id == "controlled-uncontrolled-input-mismatch" and not AST_READY:
        pytest.skip("Tree-sitter JSX parser is unavailable")
    rule = rule_cls(RuleConfig())
    facts = Facts(project_path=".")
    assert rule.analyze_ast(file_path, valid, facts) == []
    assert rule.analyze_ast(file_path, near, facts) == []
    findings = rule.analyze_ast(file_path, invalid, facts)
    assert findings, f"{rule_id} should fire on invalid sample"
    assert any(f.rule_id == rule_id for f in findings)


SEO_CASES = [
    (
        "meta-description-missing-or-generic",
        MetaDescriptionMissingOrGenericRule,
        "resources/js/Pages/Marketing/Home.tsx",
        "<Head><meta name='description' content='Comprehensive clinic platform for appointment and billing workflows.' /></Head>",
        "export default function Home(){ return <div>Home</div>; }",
        "<Head title='Home' />",
    ),
    (
        "canonical-missing-or-invalid",
        CanonicalMissingOrInvalidRule,
        "resources/js/Pages/Marketing/Home.tsx",
        "<Head><link rel='canonical' href='https://example.com/home' /></Head>",
        "export default function Home(){ return <div>Home</div>; }",
        "<Head><title>Home</title></Head>",
    ),
    (
        "robots-directive-risk",
        RobotsDirectiveRiskRule,
        "resources/js/Pages/Marketing/Home.tsx",
        "<Head><meta name='robots' content='index,follow' /></Head>",
        "<Head><meta name='robots' content='noindex,nofollow' /></Head>",
        "<Head><meta name='robots' content='noindex,nofollow' /></Head>",
    ),
    (
        "crawlable-internal-navigation-required",
        CrawlableInternalNavigationRequiredRule,
        "resources/js/Pages/Marketing/Home.tsx",
        "export default function Home(){ return <Link href='/pricing'>Pricing</Link>; }",
        "export default function Home(){ return <div>Home</div>; }",
        "export default function Home(){ return <button onClick={() => router.visit('/pricing')}>Pricing</button>; }",
    ),
    (
        "jsonld-structured-data-invalid-or-mismatched",
        JsonLdStructuredDataInvalidOrMismatchedRule,
        "resources/js/Pages/Marketing/Home.tsx",
        "<script type='application/ld+json'>{\"@context\":\"https://schema.org\",\"@type\":\"WebPage\"}</script>",
        "export default function Home(){ return <div>Home</div>; }",
        "<script type='application/ld+json'>{\"@context\":\"https://schema.org\",}</script>",
    ),
    (
        "h1-singleton-violation",
        H1SingletonViolationRule,
        "resources/js/Pages/Marketing/Home.tsx",
        "export default function Home(){ return <main><h1>Clinic Platform</h1><h2>Subheading</h2></main>; }",
        "export default function Home(){ return <div>Home</div>; }",
        "export default function Home(){ return <main><h1>One</h1><h1>Two</h1></main>; }",
    ),
    (
        "page-indexability-conflict",
        PageIndexabilityConflictRule,
        "resources/js/Pages/Marketing/Home.tsx",
        "<Head><meta name='robots' content='index,follow' /><link rel='canonical' href='https://example.com/home' /></Head>",
        "<Head><meta name='robots' content='noindex,nofollow' /></Head>",
        "<Head><meta name='robots' content='noindex,nofollow' /><link rel='canonical' href='https://example.com/home' /></Head>",
    ),
]


@pytest.mark.parametrize("rule_id,rule_cls,file_path,valid,near,invalid", SEO_CASES)
def test_react_seo_rules_valid_near_invalid(rule_id, rule_cls, file_path, valid, near, invalid):
    rule = rule_cls(RuleConfig())
    internal_facts = Facts(project_path=".")
    public_facts = _public_facts()
    assert rule.analyze_regex(file_path, valid, public_facts) == []
    assert rule.analyze_regex(file_path, near, internal_facts) == []
    findings = rule.analyze_regex(file_path, invalid, public_facts)
    assert findings, f"{rule_id} should fire on invalid sample"
    assert any(f.rule_id == rule_id for f in findings)


def test_ref_access_during_render_ignores_non_ref_current_tokens():
    rule = RefAccessDuringRenderRule(RuleConfig())
    facts = Facts(project_path=".")
    content = (
        "export default function Pagination({ pagination }) {"
        " return <span>{pagination.current_page}</span>;"
        "}"
    )
    assert rule.analyze_ast("resources/js/Pages/Admin/Pagination.tsx", content, facts) == []


def test_missing_empty_state_ignores_positive_length_guard():
    rule = MissingEmptyStateRule(RuleConfig())
    facts = Facts(project_path=".")
    content = (
        "export default function Login({ features }) {"
        " return <section>{features.length > 0 && features.map((feature) => <div key={feature.id}>{feature.name}</div>)}</section>;"
        "}"
    )
    assert rule.analyze_ast("resources/js/Pages/Auth/Login.tsx", content, facts) == []


def test_meta_description_accepts_dynamic_expression_content():
    rule = MetaDescriptionMissingOrGenericRule(RuleConfig())
    findings = rule.analyze_regex(
        "resources/js/Pages/Errors/404.tsx",
        "<Head title={t('errors.notFound.title')}><meta name=\"description\" content={t('errors.notFound.description')} /></Head>",
        _public_facts(),
    )
    assert findings == []


def test_h1_singleton_ignores_layout_title_delegation_and_types_file():
    rule = H1SingletonViolationRule(RuleConfig())
    facts = _public_facts()
    delegated = (
        "export default function Dashboard(){"
        " return <AdminLayout title={t('admin.dashboard.title')}><div>body</div></AdminLayout>;"
        "}"
    )
    assert rule.analyze_regex("resources/js/Pages/Admin/Dashboard.tsx", delegated, facts) == []
    assert rule.analyze_regex("resources/js/Pages/Admin/Dashboard.types.ts", "export type DashboardProps = { title: string }", facts) == []


def test_h1_singleton_ignores_inertia_shell_template():
    rule = H1SingletonViolationRule(RuleConfig())
    facts = _public_facts()
    shell = "<!doctype html><html><body><div id='app'>@inertia</div></body></html>"
    assert rule.analyze_regex("resources/views/app.blade.php", shell, facts) == []


def test_react_seo_context_matrix_entries_exist():
    matrix = ContextProfileMatrix.load_default()
    for rule_id in {
        "avoid-props-to-state-copy",
        "props-state-sync-effect-smell",
        "controlled-uncontrolled-input-mismatch",
        "usememo-overuse",
        "usecallback-overuse",
        "context-oversized-provider",
        "lazy-without-suspense",
        "suspense-fallback-missing",
        "stale-closure-in-timer",
        "stale-closure-in-listener",
        "duplicate-key-source",
        "missing-loading-state",
        "missing-empty-state",
        "ref-access-during-render",
        "ref-used-as-reactive-state",
        "meta-description-missing-or-generic",
        "canonical-missing-or-invalid",
        "robots-directive-risk",
        "crawlable-internal-navigation-required",
        "jsonld-structured-data-invalid-or-mismatched",
        "h1-singleton-violation",
        "page-indexability-conflict",
    }:
        assert rule_id in matrix.rule_behavior


def test_react_seo_context_calibration_examples():
    matrix = ContextProfileMatrix.load_default()
    realtime_ctx = matrix.resolve_context(
        explicit_project_type="realtime_game_control_platform",
        explicit_profile="layered",
        explicit_capabilities={"mixed_public_dashboard": True},
    )
    public_ctx = matrix.resolve_context(
        explicit_project_type="public_website_with_dashboard",
        explicit_profile="layered",
        explicit_capabilities={"public_marketing_site": True},
    )

    realtime_robots = matrix.calibrate_rule("robots-directive-risk", realtime_ctx)
    public_robots = matrix.calibrate_rule("robots-directive-risk", public_ctx)
    assert realtime_robots.get("enabled") is False
    assert public_robots.get("severity") == "high"

    realtime_overuse = matrix.calibrate_rule("usememo-overuse", realtime_ctx)
    public_overuse = matrix.calibrate_rule("usememo-overuse", public_ctx)
    assert realtime_overuse.get("enabled") is False
    assert public_overuse.get("enabled") is True


def test_react_seo_rules_present_in_profiles():
    required_ids = {
        "avoid-props-to-state-copy",
        "props-state-sync-effect-smell",
        "controlled-uncontrolled-input-mismatch",
        "usememo-overuse",
        "usecallback-overuse",
        "context-oversized-provider",
        "lazy-without-suspense",
        "suspense-fallback-missing",
        "stale-closure-in-timer",
        "stale-closure-in-listener",
        "duplicate-key-source",
        "missing-loading-state",
        "missing-empty-state",
        "ref-access-during-render",
        "ref-used-as-reactive-state",
        "meta-description-missing-or-generic",
        "canonical-missing-or-invalid",
        "robots-directive-risk",
        "crawlable-internal-navigation-required",
        "jsonld-structured-data-invalid-or-mismatched",
        "h1-singleton-violation",
        "page-indexability-conflict",
    }
    backend_root = Path(__file__).resolve().parents[1]
    for profile in ("startup", "balanced", "strict"):
        ruleset = Ruleset.load(backend_root / "rulesets" / f"{profile}.yaml")
        for rule_id in required_ids:
            assert rule_id in ruleset.rules, f"{rule_id} missing in {profile}"
            assert ruleset.rules[rule_id].enabled is True
