from core.ruleset import RuleConfig
from rules.react.hooks_in_conditional_or_loop import HooksInConditionalOrLoopRule
from rules.react.missing_key_on_list_render import MissingKeyOnListRenderRule
from rules.react.hardcoded_user_facing_strings import HardcodedUserFacingStringsRule
from rules.react.color_contrast_ratio import ColorContrastRatioRule
from rules.react.interactive_element_a11y import InteractiveElementA11yRule
from rules.react.form_label_association import FormLabelAssociationRule
from rules.react.page_title_missing import PageTitleMissingRule
from schemas.facts import Facts


def test_hooks_in_conditional_or_loop_positive_and_negative():
    rule = HooksInConditionalOrLoopRule(RuleConfig())
    facts = Facts(project_path="x")

    pos = """
function Page({ enabled }) {
  if (enabled) {
    useEffect(() => {});
  }
  return null;
}
"""
    neg = """
function Page() {
  useEffect(() => {}, []);
  return null;
}
"""
    assert rule.analyze_regex("resources/js/Pages/Page.tsx", pos, facts)
    assert not rule.analyze_regex("resources/js/Pages/Page.tsx", neg, facts)


def test_missing_key_on_list_render_positive_and_negative():
    rule = MissingKeyOnListRenderRule(RuleConfig())
    facts = Facts(project_path="x")

    pos = "return items.map((item) => <li>{item.name}</li>);"
    neg = "return items.map((item) => <li key={item.id}>{item.name}</li>);"
    assert rule.analyze_regex("resources/js/Components/List.tsx", pos, facts)
    assert not rule.analyze_regex("resources/js/Components/List.tsx", neg, facts)


def test_hardcoded_user_facing_strings_positive_and_negative():
    rule = HardcodedUserFacingStringsRule(RuleConfig())
    facts = Facts(project_path="x")
    facts.project_context.has_i18n = True

    pos = "<h1>Patient Details</h1>"
    neg = "<h1>{t('patient.details')}</h1>"
    assert rule.analyze_regex("resources/js/Pages/Patient.tsx", pos, facts)
    assert not rule.analyze_regex("resources/js/Pages/Patient.tsx", neg, facts)


def test_interactive_element_a11y_positive_and_negative():
    rule = InteractiveElementA11yRule(RuleConfig())
    facts = Facts(project_path="x")

    pos = "<div onClick={openModal}>Open</div>"
    neg = "<div role='button' tabIndex={0} onClick={openModal} onKeyDown={onKeyDown}>Open</div>"
    assert rule.analyze_regex("resources/js/Components/ButtonLike.tsx", pos, facts)
    assert not rule.analyze_regex("resources/js/Components/ButtonLike.tsx", neg, facts)


def test_form_label_association_positive_and_negative():
    rule = FormLabelAssociationRule(RuleConfig())
    facts = Facts(project_path="x")

    pos = "<label>Patient Name</label><input id='patient_name' />"
    neg_html_for = "<label htmlFor='patient_name'>Patient Name</label><input id='patient_name' />"
    neg_nested = "<label>Patient Name <input /></label>"

    assert rule.analyze_regex("resources/js/Pages/Form.tsx", pos, facts)
    assert not rule.analyze_regex("resources/js/Pages/Form.tsx", neg_html_for, facts)
    assert not rule.analyze_regex("resources/js/Pages/Form.tsx", neg_nested, facts)


def test_hardcoded_user_facing_strings_ignores_key_like_tokens():
    rule = HardcodedUserFacingStringsRule(RuleConfig())
    facts = Facts(project_path="x")
    facts.project_context.has_i18n = True

    key_like = "<div>ui.patient.details_title</div>"
    findings = rule.analyze_regex("resources/js/Pages/Patient.tsx", key_like, facts)
    assert findings == []


def test_hardcoded_user_facing_strings_ignores_short_single_word_labels():
    rule = HardcodedUserFacingStringsRule(RuleConfig())
    facts = Facts(project_path="x")
    facts.project_context.has_i18n = True

    findings = rule.analyze_regex("resources/js/Pages/Patient.tsx", "<button>Continue</button>", facts)
    assert findings == []


def test_hardcoded_user_facing_strings_skips_projects_without_i18n_context():
    rule = HardcodedUserFacingStringsRule(RuleConfig())
    facts = Facts(project_path="x")

    findings = rule.analyze_regex("resources/js/Pages/Patient.tsx", "<h1>Patient Details</h1>", facts)
    assert findings == []


def test_color_contrast_ratio_uses_text_and_background_pair():
    rule = ColorContrastRatioRule(RuleConfig())
    facts = Facts(project_path="x")

    bad = '<p className="text-gray-300 bg-white">Low contrast body copy</p>'
    good = '<p className="text-gray-400 bg-slate-900">Readable on dark surface</p>'

    assert rule.analyze_regex("resources/js/Pages/Patient.tsx", bad, facts)
    assert rule.analyze_regex("resources/js/Pages/Patient.tsx", good, facts) == []


def test_interactive_element_a11y_ignores_storybook_files():
    rule = InteractiveElementA11yRule(RuleConfig())
    facts = Facts(project_path="x")

    story = "<div onClick={openModal}>Open</div>"
    findings = rule.analyze_regex("resources/js/Stories/Button.stories.tsx", story, facts)
    assert findings == []


def test_form_label_association_ignores_aria_labelledby_link():
    rule = FormLabelAssociationRule(RuleConfig())
    facts = Facts(project_path="x")

    content = """
<label id="patient_name_label">Patient Name</label>
<input aria-labelledby="patient_name_label" />
"""
    findings = rule.analyze_regex("resources/js/Pages/Form.tsx", content, facts)
    assert findings == []


def test_page_title_missing_flags_generic_head_title():
    rule = PageTitleMissingRule(RuleConfig())
    facts = Facts(project_path="x")
    content = """
import { Head } from "@inertiajs/react";

export default function Dashboard() {
  return (
    <>
      <Head title="Page" />
      <div>Dashboard</div>
    </>
  );
}
"""
    findings = rule.analyze_regex("resources/js/Pages/Dashboard.tsx", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "page-title-missing"
    assert "generic" in findings[0].title.lower()


def test_page_title_missing_skips_dynamic_layout_title_prop():
    rule = PageTitleMissingRule(RuleConfig())
    facts = Facts(project_path="x")
    content = """
export default function Dashboard({ pageTitle }) {
  return (
    <AuthenticatedLayout title={pageTitle}>
      <div>Dashboard</div>
    </AuthenticatedLayout>
  );
}
"""
    findings = rule.analyze_regex("resources/js/Pages/Dashboard.tsx", content, facts)
    assert findings == []


def test_page_title_missing_skips_non_component_module_with_page_name():
    rule = PageTitleMissingRule(RuleConfig())
    facts = Facts(project_path="x")
    content = """
export const columns = [
  { key: "name", label: "Name" },
];
"""
    findings = rule.analyze_regex("resources/js/Pages/Patients/Show.tsx", content, facts)
    assert findings == []


def test_page_title_missing_skips_utilities_index_module():
    rule = PageTitleMissingRule(RuleConfig())
    facts = Facts(project_path="x")
    content = """
export const DAYS = [0, 1, 2, 3, 4, 5, 6] as const;
export const DAY_ABBREV = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
"""

    findings = rule.analyze_regex("resources/js/utilities/schedule/index.ts", content, facts)
    assert findings == []
