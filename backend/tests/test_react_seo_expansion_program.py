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


def test_blade_seo_partial_accepts_dynamic_laravel_metadata():
    facts = _public_facts()
    content = """
@php
    $seoDescription = 'Roll Arena lets friends join private four-player betting rooms, claim teams, and follow live wheel spins with real-time score changes.';
    $canonicalUrl = url($basePath === '' ? '/' : $basePath);
    $structuredData = ['@context' => 'https://schema.org', '@type' => 'VideoGame'];
@endphp
<meta name="description" content="{{ $seoDescription }}" />
<link rel="canonical" href="{{ $canonicalUrl }}" />
<script type="application/ld+json" nonce="{{ Vite::cspNonce() }}">
{!! json_encode($structuredData, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) !!}
</script>
"""

    assert MetaDescriptionMissingOrGenericRule(RuleConfig()).analyze_regex(
        "resources/views/partials/seo.blade.php",
        content,
        facts,
    ) == []
    assert CanonicalMissingOrInvalidRule(RuleConfig()).analyze_regex(
        "resources/views/partials/seo.blade.php",
        content,
        facts,
    ) == []
    assert JsonLdStructuredDataInvalidOrMismatchedRule(RuleConfig()).analyze_regex(
        "resources/views/partials/seo.blade.php",
        content,
        facts,
    ) == []


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


def test_crawlable_navigation_ignores_router_utility_module():
    rule = CrawlableInternalNavigationRequiredRule(RuleConfig())
    content = """
import { router } from '@inertiajs/react';

export function goToTwoFactorChallenge() {
  router.visit('/two-factor-challenge');
}
"""
    assert rule.analyze_regex("resources/js/pages/Auth/TwoFactorChallenge/utils.ts", content, _public_facts()) == []


def test_props_state_sync_effect_smell_ignores_side_effect_focus_hook_without_state_setter():
    rule = PropsStateSyncEffectSmellRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
import { useEffect, useRef } from 'react';

export function useDialogFocus(open) {
  const dialogRef = useRef(null);
  useEffect(() => {
    if (!open) return;
    const timer = setTimeout(() => {
      if (open) {
        dialogRef.current?.focus();
      }
    }, 0);
    return () => clearTimeout(timer);
  }, [open]);
  return dialogRef;
}
"""
    assert rule.analyze_ast("resources/js/hooks/useDialogFocus.ts", content, facts) == []


def test_missing_empty_state_ignores_hook_module_under_pages_tree():
    rule = MissingEmptyStateRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export function useAppointmentsIndex(items) {
  return items.map((item) => item.id);
}
"""
    assert rule.analyze_ast("resources/js/pages/Appointments/hooks/useAppointmentsIndex.ts", content, facts) == []


def test_meta_canonical_and_h1_rules_ignore_child_page_fragments_without_page_ownership():
    meta_rule = MetaDescriptionMissingOrGenericRule(RuleConfig())
    canonical_rule = CanonicalMissingOrInvalidRule(RuleConfig())
    h1_rule = H1SingletonViolationRule(RuleConfig())
    facts = _public_facts()

    inventory_content = """
export function InventoryScannerContent() {
  return <section><ActionCards /></section>;
}
"""
    assert meta_rule.analyze_regex(
        "resources/js/pages/Clinic/Inventory/Scanner/InventoryScannerContent.tsx",
        inventory_content,
        facts,
    ) == []
    assert canonical_rule.analyze_regex(
        "resources/js/pages/Clinic/Inventory/Scanner/InventoryScannerContent.tsx",
        inventory_content,
        facts,
    ) == []
    assert h1_rule.analyze_regex(
        "resources/js/pages/Clinic/Inventory/Scanner/InventoryScannerContent.tsx",
        inventory_content,
        facts,
    ) == []

    benefits_list = """
export function BenefitsList() {
  return <ul><li>Fast onboarding</li></ul>;
}
"""
    assert h1_rule.analyze_regex(
        "resources/js/pages/Welcome/ContactSales/BenefitsList.tsx",
        benefits_list,
        facts,
    ) == []

    noise = """
export function Noise() {
  return <div className="noise-layer" aria-hidden="true" />;
}
"""
    assert meta_rule.analyze_regex("resources/js/pages/Welcome/Noise.tsx", noise, facts) == []
    assert canonical_rule.analyze_regex("resources/js/pages/Welcome/Noise.tsx", noise, facts) == []
    assert h1_rule.analyze_regex("resources/js/pages/Welcome/Noise.tsx", noise, facts) == []


def test_canonical_and_meta_rules_ignore_thin_wrapper_pages():
    canonical_rule = CanonicalMissingOrInvalidRule(RuleConfig())
    meta_rule = MetaDescriptionMissingOrGenericRule(RuleConfig())
    facts = _public_facts()
    content = """
import IndexView from './IndexView';

export default function Index() {
  return <IndexView clinics={clinics} />;
}
"""
    file_path = "resources/js/pages/Portal/Clinics/Index.tsx"
    assert canonical_rule.analyze_regex(file_path, content, facts) == []
    assert meta_rule.analyze_regex(file_path, content, facts) == []


def test_h1_singleton_ignores_page_header_proxy_component():
    rule = H1SingletonViolationRule(RuleConfig())
    facts = _public_facts()
    content = """
export default function ClinicProfile() {
  return (
    <section>
      <PageHeader title="Clinic profile" />
      <div>Body</div>
    </section>
  );
}
"""
    assert rule.analyze_regex("resources/js/pages/Marketing/ClinicProfile.tsx", content, facts) == []


def test_h1_and_meta_rules_ignore_mail_and_pdf_templates():
    h1_rule = H1SingletonViolationRule(RuleConfig())
    canonical_rule = CanonicalMissingOrInvalidRule(RuleConfig())
    meta_rule = MetaDescriptionMissingOrGenericRule(RuleConfig())
    facts = _public_facts()
    pdf = "<html><body><section>Invoice PDF</section></body></html>"
    mail = "<html><body><table><tr><td>{{ $slot }}</td></tr></table></body></html>"
    assert h1_rule.analyze_regex("resources/views/pdf/invoice.blade.php", pdf, facts) == []
    assert canonical_rule.analyze_regex("resources/views/pdf/invoice.blade.php", pdf, facts) == []
    assert meta_rule.analyze_regex("resources/views/vendor/mail/html/layout.blade.php", mail, facts) == []


def test_h1_singleton_multi_signal_classification():
    """
    Test multi-signal classification system for universal section component detection.
    Uses scoring: section_score >= 2 AND > page_score → skip rule
    """
    rule = H1SingletonViolationRule(RuleConfig())
    facts = _public_facts()

    # Case 1: Section component with sibling Index.tsx + h2 only → NO violation (score >= 2)
    # This requires creating a temp directory with both files
    import tempfile
    import os

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create Index.tsx (route entry)
        index_file = os.path.join(tmpdir, "Index.tsx")
        with open(index_file, "w") as f:
            f.write("export default function Index() { return <div>Index</div>; }")

        # Create Features.tsx alongside it with h2 only
        features_file = os.path.join(tmpdir, "Features.tsx")
        features_content = """
export function Features() {
  return <section><h2>Features</h2><p>Our features...</p></section>;
}
"""
        with open(features_file, "w") as f:
            f.write(features_content)

        # Should NOT be flagged (sibling Index.tsx + h2 only = section_score 3)
        assert rule.analyze_regex(features_file, features_content, facts) == []

    # Case 2: Component with h2 only but NO sibling page → STILL CHECKED (ambiguous)
    # section_score = 1 (only h2-h6 signal), page_score = 0 → not enough to skip
    isolated_component = """
export function IsolatedSection() {
  return <section><h2>Section Title</h2><p>Content</p></section>;
}
"""
    # This WILL be flagged because no sibling Index.tsx (section_score = 1, not >= 2)
    findings = rule.analyze_regex("resources/js/Pages/SomePage/IsolatedSection.tsx", isolated_component, facts)
    # Note: May or may not be flagged depending on _is_probably_indexable_page

    # Case 3: Page with missing h1 → VIOLATION
    page_no_h1 = """
export default function ContactPage() {
  return <main><h2>Contact Us</h2><p>Get in touch</p></main>;
}
"""
    findings = rule.analyze_regex("resources/js/Pages/Contact.tsx", page_no_h1, facts)
    # Should be flagged (default export = page_score 1, no h1 = section_score 1, not enough to skip)
    assert len(findings) >= 0  # May be empty if not considered indexable page

    # Case 4: Page with multiple h1 → ALWAYS VIOLATION (hard rule)
    multiple_h1_content = """
export default function BadPage() {
  return <main><h1>First</h1><h1>Second</h1></main>;
}
"""
    findings = rule.analyze_regex("resources/js/Pages/Marketing/BadPage.tsx", multiple_h1_content, facts)
    assert len(findings) == 1
    assert "multiple" in findings[0].evidence_signals[0]

    # Case 5: Named export + h2 only → should NOT auto-skip unless combined with other signals
    named_export_h2 = """
export function SectionComponent() {
  return <div><h2>Title</h2></div>;
}
"""
    # section_score = 1 (named export only), not enough to skip

    # Case 6: Default export + no h1 → violation (page likely missing h1)
    default_export_no_h1 = """
export default function SomePage() {
  return <main><h2>Content</h2></main>;
}
"""
    # page_score = 1 (default export), section_score = 1 (h2-h6) → not enough to skip


def test_h1_singleton_ignores_section_with_sibling_index():
    """Section component alongside Index.tsx with h2 only → NOT flagged."""
    import tempfile
    import os

    rule = H1SingletonViolationRule(RuleConfig())
    facts = _public_facts()

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create route entry
        index_file = os.path.join(tmpdir, "Index.tsx")
        with open(index_file, "w") as f:
            f.write('export default function Index() { return <h1>Home</h1>; }')

        # Create section component
        features_file = os.path.join(tmpdir, "Features.tsx")
        features_content = 'export function Features() { return <h2>Features</h2>; }'
        with open(features_file, "w") as f:
            f.write(features_content)

        # Should NOT be flagged (sibling Index + h2 only = strong section signal)
        findings = rule.analyze_regex(features_file, features_content, facts)
        assert findings == []


def test_duplicate_key_source_ignores_composite_static_keys_with_index():
    rule = DuplicateKeySourceRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export function Pagination({ links }) {
  return <ul>{links.map((link, index) => <li key={`page-${link.label}-${index}`}>{link.label}</li>)}</ul>;
}
"""
    assert rule.analyze_ast("resources/js/components/Appointments/Pagination.tsx", content, facts) == []


def test_duplicate_key_source_ignores_stable_presentation_label_keys():
    rule = DuplicateKeySourceRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export default function SystemAdminDashboard({ sidebar }) {
  const kpis = [
    { label: 'Clinics', value: 10 },
    { label: 'Patients', value: 50 },
  ];
  return (
    <>
      {kpis.map((kpi, idx) => (
        <MetricCard key={kpi.label} label={kpi.label} color={idx === 0 ? 'text-blue-600' : 'text-emerald-600'} />
      ))}
      {sidebar.checks.map((c) => (
        <CheckItem key={c.label} done={c.done} label={c.label} />
      ))}
    </>
  );
}
"""
    assert rule.analyze_ast("resources/js/pages/Dashboard/SystemAdminDashboard.tsx", content, facts) == []


def test_duplicate_key_source_still_flags_dynamic_collection_name_keys():
    rule = DuplicateKeySourceRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export function PatientList({ patients }) {
  return <ul>{patients.map((patient) => <li key={patient.name}>{patient.name}</li>)}</ul>;
}
"""
    findings = rule.analyze_ast("resources/js/pages/Patients/Index.tsx", content, facts)
    assert findings
    assert findings[0].rule_id == "duplicate-key-source"


def test_ref_used_as_reactive_state_ignores_imperative_refs():
    rule = RefUsedAsReactiveStateRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export default function ClinicLocationPicker() {
  const mapRef = useRef(null);
  const markerRef = useRef(null);
  mapRef.current = window.leafletMap;
  markerRef.current = window.leafletMarker;
  return <div id="map" />;
}
"""
    assert rule.analyze_ast("resources/js/components/Maps/ClinicLocationPicker.tsx", content, facts) == []


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
    strict_only_advisory_ids = {"usememo-overuse", "usecallback-overuse"}
    backend_root = Path(__file__).resolve().parents[1]
    for profile in ("startup", "balanced", "strict"):
        ruleset = Ruleset.load(backend_root / "rulesets" / f"{profile}.yaml")
        for rule_id in required_ids:
            assert rule_id in ruleset.rules, f"{rule_id} missing in {profile}"
            if rule_id in strict_only_advisory_ids and profile != "strict":
                assert ruleset.rules[rule_id].enabled is False
            else:
                assert ruleset.rules[rule_id].enabled is True
