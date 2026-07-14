from core.ruleset import RuleConfig
from rules.react.css_tailwind_accessibility_rules import (
    TailwindAppearanceNoneRiskRule,
    TailwindMotionReduceMissingRule,
)
from rules.react.css_tailwind_best_practice_rules import (
    TailwindArbitraryRadiusShadowRule,
    TailwindArbitrarySpacingRule,
    TailwindArbitraryTextSizeRule,
    TailwindArbitraryValueOveruseRule,
)
from schemas.facts import Facts


def _facts() -> Facts:
    return Facts(project_path=".", npm_packages={"tailwindcss": "^4.0.0"})


def test_tailwind_rules_ignore_examples_in_comments_and_ordinary_strings() -> None:
    source = """
// <div className="text-[12px]">comment example</div>
const documentation = '<div className="text-[12px]">string example</div>';
export function Plain() { return <div className="text-sm">Real code</div>; }
"""

    findings = TailwindArbitraryTextSizeRule(RuleConfig()).analyze_regex(
        "src/Plain.tsx",
        source,
        _facts(),
    )

    assert findings == []


def test_tailwind_rules_read_braced_attributes_and_class_composition_helpers() -> None:
    source = """
export function Card() {
  const classes = cn("p-[16px]", condition && "text-[12px]");
  return <div className={classes}><span className={'text-[14px]'}>Card</span></div>;
}
"""

    spacing = TailwindArbitrarySpacingRule(RuleConfig()).analyze_regex("src/Card.tsx", source, _facts())
    text = TailwindArbitraryTextSizeRule(RuleConfig()).analyze_regex("src/Card.tsx", source, _facts())

    assert len(spacing) == 1
    assert len(text) == 2


def test_tailwind_dynamic_template_keeps_static_evidence_without_guessing_expression() -> None:
    source = """
export function Panel({ active }) {
  return <div className={`p-[16px] ${active ? 'bg-blue-500' : 'bg-gray-500'} w-[384px] text-[12px]`} />;
}
"""

    findings = TailwindArbitraryValueOveruseRule(RuleConfig()).analyze_regex(
        "src/Panel.tsx",
        source,
        _facts(),
    )

    assert len(findings) == 1
    assert "arbitrary_count=3" in findings[0].evidence_signals


def test_tailwind_arbitrary_variants_are_tokenized_but_custom_shadows_are_not_guessed() -> None:
    variant_source = '<div className="[&>*]:p-[16px]" />'
    shadow_source = """
const card = cva("shadow-[0_1px_2px_rgba(0,0,0,0.06)]");
const panel = cva("shadow-[0_1px_2px_rgba(0,0,0,0.06)]");
"""

    spacing = TailwindArbitrarySpacingRule(RuleConfig()).analyze_regex(
        "src/List.tsx",
        variant_source,
        _facts(),
    )
    shadow = TailwindArbitraryRadiusShadowRule(RuleConfig()).analyze_regex(
        "src/Card.tsx",
        shadow_source,
        _facts(),
    )

    assert len(spacing) == 1
    assert shadow == []


def test_tailwind_arbitrary_rules_skip_theme_values_and_intentional_exceptions() -> None:
    source = """
export function ThemeCard() {
  return <div className="text-[var(--font-size-card)] p-[var(--space-card)] p-[15px] rounded-[13px] shadow-[0_1px_2px_rgba(0,0,0,0.06)]" />;
}
"""

    assert TailwindArbitraryTextSizeRule(RuleConfig()).analyze_regex("src/Card.tsx", source, _facts()) == []
    assert TailwindArbitrarySpacingRule(RuleConfig()).analyze_regex("src/Card.tsx", source, _facts()) == []
    assert TailwindArbitraryRadiusShadowRule(RuleConfig()).analyze_regex("src/Card.tsx", source, _facts()) == []


def test_tailwind_overuse_skips_class_strings_made_entirely_of_theme_references() -> None:
    source = '<div className="p-[var(--space-card)] text-[var(--font-card)] rounded-[var(--radius-card)]" />'

    findings = TailwindArbitraryValueOveruseRule(RuleConfig()).analyze_regex(
        "src/Card.tsx",
        source,
        _facts(),
    )

    assert findings == []


def test_motion_guard_must_apply_to_the_motion_behavior() -> None:
    unrelated_guard = '<div className="animate-spin motion-safe:opacity-50" />'
    real_fallback = '<div className="animate-spin motion-reduce:animate-none" />'
    rule = TailwindMotionReduceMissingRule(RuleConfig())

    assert len(rule.analyze_regex("src/Spinner.tsx", unrelated_guard, _facts())) == 1
    assert rule.analyze_regex("src/Spinner.tsx", real_fallback, _facts()) == []


def test_appearance_none_parser_handles_arrow_handlers_and_requires_focus_variant() -> None:
    safe = """
<select onChange={(event) => setValue(event.target.value)}
        className={cn("appearance-none", "border px-3", "focus-visible:ring-2")}>
  <option>A</option>
</select>
"""
    unsafe = """
<select onChange={(event) => setValue(event.target.value)}
        className={cn("appearance-none", "border px-3", "ring-2")}>
  <option>A</option>
</select>
"""
    rule = TailwindAppearanceNoneRiskRule(RuleConfig())

    assert rule.analyze_regex("src/Select.tsx", safe, _facts()) == []
    findings = rule.analyze_regex("src/Select.tsx", unsafe, _facts())
    assert len(findings) == 1
    assert findings[0].line_start == 2
