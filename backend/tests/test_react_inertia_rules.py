from core.ruleset import RuleConfig
from rules.react.no_inline_types import NoInlineTypesRule
from rules.react.no_inline_services import NoInlineServicesRule
from rules.react.inertia_page_missing_head import InertiaPageMissingHeadRule
from rules.react.inertia_internal_link_anchor import InertiaInternalLinkAnchorRule
from rules.react.inertia_form_uses_fetch import InertiaFormUsesFetchRule
from schemas.facts import Facts, ReactComponentInfo


def test_no_inline_types_flags_ast_component_metadata():
    facts = Facts(project_path=".")
    facts.react_components.append(
        ReactComponentInfo(
            name="PatientPage",
            file_path="resources/js/Pages/Patients/Index.tsx",
            file_hash="deadbeef",
            line_start=1,
            line_end=80,
            loc=80,
            has_inline_type_defs=True,
            inline_type_names=["PatientRow", "PatientFilters"],
        )
    )

    findings = NoInlineTypesRule(RuleConfig()).run(facts, project_type="laravel_inertia_react").findings
    assert len(findings) == 1
    assert findings[0].rule_id == "no-inline-types"


def test_no_inline_services_flags_ast_component_metadata():
    facts = Facts(project_path=".")
    facts.react_components.append(
        ReactComponentInfo(
            name="PatientPage",
            file_path="resources/js/Pages/Patients/Index.tsx",
            file_hash="deadbeef",
            line_start=1,
            line_end=80,
            loc=80,
            has_inline_helper_fns=True,
            inline_helper_names=["fetchPatientRows", "persistPatientDraft"],
        )
    )

    findings = NoInlineServicesRule(RuleConfig()).run(facts, project_type="laravel_inertia_react").findings
    assert len(findings) == 1
    assert findings[0].rule_id == "no-inline-services"


def test_no_inline_services_skips_trivial_ui_handlers():
    facts = Facts(project_path=".")
    facts.react_components.append(
        ReactComponentInfo(
            name="BookingForm",
            file_path="resources/js/Components/BookingForm.tsx",
            file_hash="deadbeef",
            line_start=1,
            line_end=60,
            loc=60,
            has_inline_helper_fns=True,
            inline_helper_names=["handleBack", "toggleMenu", "focusIndex", "emitValue"],
        )
    )

    findings = NoInlineServicesRule(RuleConfig()).run(facts, project_type="laravel_inertia_react").findings
    assert findings == []


def test_no_inline_types_skips_hook_modules():
    facts = Facts(project_path=".")
    facts.react_components.append(
        ReactComponentInfo(
            name="usePatientSearch",
            file_path="resources/js/hooks/usePatientSearch.ts",
            file_hash="deadbeef",
            line_start=1,
            line_end=80,
            loc=80,
            has_inline_type_defs=True,
            inline_type_names=["PatientSearchParams"],
        )
    )

    findings = NoInlineTypesRule(RuleConfig()).run(facts, project_type="laravel_inertia_react").findings
    assert findings == []


def test_no_inline_services_skips_colocated_utils_modules():
    facts = Facts(project_path=".")
    facts.react_components.append(
        ReactComponentInfo(
            name="IndexUtils",
            file_path="resources/js/pages/Portal/Subscriptions/utils.ts",
            file_hash="deadbeef",
            line_start=1,
            line_end=60,
            loc=60,
            has_inline_helper_fns=True,
            inline_helper_names=["formatPlanPrice"],
        )
    )

    findings = NoInlineServicesRule(RuleConfig()).run(facts, project_type="laravel_inertia_react").findings
    assert findings == []


def test_no_inline_services_skips_pure_local_utilities_inside_component():
    facts = Facts(project_path=".")
    facts.react_components.append(
        ReactComponentInfo(
            name="Modal",
            file_path="resources/js/components/UI/Modal.tsx",
            file_hash="deadbeef",
            line_start=1,
            line_end=120,
            loc=120,
            has_inline_helper_fns=True,
            inline_helper_names=["getFocusableElements"],
        )
    )

    findings = NoInlineServicesRule(RuleConfig()).run(facts, project_type="laravel_inertia_react").findings
    assert findings == []


def test_inertia_page_missing_head_flags_page_without_head():
    rule = InertiaPageMissingHeadRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
import React from "react";

export default function Dashboard() {
  return <div>Dashboard</div>;
}
"""

    findings = rule.analyze_regex("resources/js/Pages/Dashboard.tsx", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "inertia-page-missing-head"


def test_inertia_page_missing_head_skips_page_with_head():
    rule = InertiaPageMissingHeadRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
import { Head } from "@inertiajs/react";

export default function Dashboard() {
  return <>
    <Head title="Dashboard" />
    <div>Dashboard</div>
  </>;
}
"""

    findings = rule.analyze_regex("resources/js/Pages/Dashboard.tsx", content, facts)
    assert findings == []


def test_inertia_page_missing_head_skips_layout_with_title_prop():
    rule = InertiaPageMissingHeadRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
import AppLayout from "@/Layouts/AppLayout";

export default function Dashboard() {
  return (
    <AppLayout title="Dashboard">
      <div>Dashboard</div>
    </AppLayout>
  );
}
"""

    findings = rule.analyze_regex("resources/js/Pages/Dashboard.tsx", content, facts)
    assert findings == []


def test_inertia_page_missing_head_skips_layout_assignment_with_title():
    rule = InertiaPageMissingHeadRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
import AuthenticatedLayout from "@/Layouts/AuthenticatedLayout";

function Dashboard() {
  return <div>Dashboard</div>;
}

Dashboard.layout = (page) => (
  <AuthenticatedLayout title="Dashboard">
    {page}
  </AuthenticatedLayout>
);

export default Dashboard;
"""

    findings = rule.analyze_regex("resources/js/Pages/Dashboard.tsx", content, facts)
    assert findings == []


def test_inertia_page_missing_head_skips_non_page_helper_file_under_pages():
    rule = InertiaPageMissingHeadRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export const buildDashboardBreadcrumbs = () => [
  { label: "Dashboard", href: "/dashboard" },
];
"""

    findings = rule.analyze_regex("resources/js/Pages/Dashboard/helpers.ts", content, facts)
    assert findings == []


def test_inertia_page_missing_head_skips_page_local_section_component():
    rule = InertiaPageMissingHeadRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export default function DesktopScheduleGrid() {
  return <div>Grid</div>;
}
"""

    findings = rule.analyze_regex("resources/js/Pages/Appointments/Schedule/DesktopScheduleGrid.tsx", content, facts)
    assert findings == []


def test_inertia_page_missing_head_keeps_route_entry_files_in_scope():
    rule = InertiaPageMissingHeadRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export default function EditPatient() {
  return <div>Edit patient</div>;
}
"""

    findings = rule.analyze_regex("resources/js/Pages/Patients/Edit.tsx", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "inertia-page-missing-head"


def test_inertia_internal_link_anchor_flags_raw_internal_anchor():
    rule = InertiaInternalLinkAnchorRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export default function Dashboard() {
  return <a href="/patients">Patients</a>;
}
"""

    findings = rule.analyze_regex("resources/js/Pages/Dashboard.tsx", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "inertia-internal-link-anchor"


def test_inertia_form_uses_fetch_flags_form_without_useform():
    rule = InertiaFormUsesFetchRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export default function CreatePatient() {
  const submit = async (e) => {
    e.preventDefault();
    await fetch('/patients', { method: 'POST' });
  };
  return <form onSubmit={submit}><button type="submit">Save</button></form>;
}
"""

    findings = rule.analyze_regex("resources/js/Pages/Patients/Create.tsx", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "inertia-form-uses-fetch"


def test_inertia_form_uses_fetch_skips_useform_page():
    rule = InertiaFormUsesFetchRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
import { useForm } from '@inertiajs/react';

export default function CreatePatient() {
  const form = useForm({ name: '' });
  return <form onSubmit={(e) => { e.preventDefault(); form.post('/patients'); }} />;
}
"""

    findings = rule.analyze_regex("resources/js/Pages/Patients/Create.tsx", content, facts)
    assert findings == []
