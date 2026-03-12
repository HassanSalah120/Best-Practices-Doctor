from core.ruleset import RuleConfig
from rules.react.hooks_in_conditional_or_loop import HooksInConditionalOrLoopRule
from rules.react.missing_key_on_list_render import MissingKeyOnListRenderRule
from rules.react.hardcoded_user_facing_strings import HardcodedUserFacingStringsRule
from rules.react.interactive_element_a11y import InteractiveElementA11yRule
from rules.react.form_label_association import FormLabelAssociationRule
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

    key_like = "<div>ui.patient.details_title</div>"
    findings = rule.analyze_regex("resources/js/Pages/Patient.tsx", key_like, facts)
    assert findings == []


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
