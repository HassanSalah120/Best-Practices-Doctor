from core.ruleset import RuleConfig
from rules.react.anonymous_default_export_component import AnonymousDefaultExportComponentRule
from rules.react.multiple_exported_components_per_file import MultipleExportedComponentsPerFileRule
from rules.react.context_provider_inline_value import ContextProviderInlineValueRule
from rules.react.useeffect_fetch_without_abort import UseEffectFetchWithoutAbortRule
from rules.react.no_nested_components import NoNestedComponentsRule
from schemas.facts import Facts


def test_anonymous_default_export_component_flags_anonymous_function():
    rule = AnonymousDefaultExportComponentRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export default function () {
  return <div>Patients</div>;
}
"""

    findings = rule.analyze_regex("resources/js/Pages/Patients.tsx", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "anonymous-default-export-component"


def test_anonymous_default_export_component_skips_named_component():
    rule = AnonymousDefaultExportComponentRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export default function PatientsPage() {
  return <div>Patients</div>;
}
"""

    findings = rule.analyze_regex("resources/js/Pages/Patients.tsx", content, facts)
    assert findings == []


def test_multiple_exported_react_components_flags_multiple_exports():
    rule = MultipleExportedComponentsPerFileRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export function Header() {
  return <header />;
}

export const Footer = () => {
  return <footer />;
};
"""

    findings = rule.analyze_regex("resources/js/Components/Layout.tsx", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "multiple-exported-react-components"


def test_multiple_exported_react_components_skips_single_export():
    rule = MultipleExportedComponentsPerFileRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export function Header() {
  return <header />;
}
"""

    findings = rule.analyze_regex("resources/js/Components/Header.tsx", content, facts)
    assert findings == []


def test_context_provider_inline_value_flags_inline_object():
    rule = ContextProviderInlineValueRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export function AppProvider({ children }) {
  return (
    <AppContext.Provider value={{ user, setUser }}>
      {children}
    </AppContext.Provider>
  );
}
"""

    findings = rule.analyze_regex("resources/js/Context/AppProvider.tsx", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "context-provider-inline-value"


def test_context_provider_inline_value_skips_memoized_value():
    rule = ContextProviderInlineValueRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export function AppProvider({ children }) {
  const value = useMemo(() => ({ user, setUser }), [user]);
  return (
    <AppContext.Provider value={value}>
      {children}
    </AppContext.Provider>
  );
}
"""

    findings = rule.analyze_regex("resources/js/Context/AppProvider.tsx", content, facts)
    assert findings == []


def test_react_useeffect_fetch_without_abort_flags_plain_fetch():
    rule = UseEffectFetchWithoutAbortRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export function PatientsPage() {
  useEffect(() => {
    fetch('/api/patients')
      .then((r) => r.json())
      .then(setPatients);
  }, []);
  return null;
}
"""

    findings = rule.analyze_regex("resources/js/Pages/Patients.tsx", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "react-useeffect-fetch-without-abort"


def test_react_useeffect_fetch_without_abort_skips_abort_controller_cleanup():
    rule = UseEffectFetchWithoutAbortRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export function PatientsPage() {
  useEffect(() => {
    const controller = new AbortController();
    fetch('/api/patients', { signal: controller.signal })
      .then((r) => r.json())
      .then(setPatients);
    return () => controller.abort();
  }, []);
  return null;
}
"""

    findings = rule.analyze_regex("resources/js/Pages/Patients.tsx", content, facts)
    assert findings == []


def test_no_nested_components_skips_module_level_sibling_component():
    rule = NoNestedComponentsRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
function SidebarContent() {
  return <aside />;
}

export default function AuthenticatedLayout() {
  return <SidebarContent />;
}
"""

    findings = rule.analyze_regex("resources/js/layouts/AuthenticatedLayout.tsx", content, facts)
    assert findings == []


def test_no_nested_components_flags_component_defined_inside_parent():
    rule = NoNestedComponentsRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export default function AuthenticatedLayout() {
  const ImpersonationBanner = () => {
    return <div>Impersonating</div>;
  };

  return <ImpersonationBanner />;
}
"""

    findings = rule.analyze_regex("resources/js/layouts/AuthenticatedLayout.tsx", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "no-nested-components"
