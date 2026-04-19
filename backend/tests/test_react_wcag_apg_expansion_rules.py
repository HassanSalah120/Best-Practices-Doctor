from __future__ import annotations

from pathlib import Path

import pytest

from core.context_profiles import ContextProfileMatrix
from core.ruleset import RuleConfig, Ruleset
from rules.react.focus_indicator_missing import FocusIndicatorMissingRule
from rules.react.form_label_association import FormLabelAssociationRule
from rules.react.interactive_element_a11y import InteractiveElementA11yRule
from rules.react.jsx_tree_sitter import JsxTreeSitterHelper
from rules.react.modal_trap_focus import ModalTrapFocusRule
from rules.react.skip_link_missing import SkipLinkMissingRule
from rules.react.touch_target_size import TouchTargetSizeRule
from rules.react.wcag_apg_ast_rules import (
    APGAccordionDisclosureContractRule,
    APGComboboxContractRule,
    APGMenuButtonContractRule,
    APGTabsKeyboardContractRule,
    DialogFocusRestoreMissingRule,
    InteractiveAccessibleNameRequiredRule,
    JsxAriaAttributeFormatRule,
    OutsideClickWithoutKeyboardFallbackRule,
    SemanticWrapperBreakageRule,
)
from rules.react.css_tailwind_accessibility_rules import (
    CssColorOnlyStateIndicatorRule,
    CssFocusOutlineWithoutReplacementRule,
    CssHoverOnlyInteractionRule,
    TailwindAppearanceNoneRiskRule,
    TailwindMotionReduceMissingRule,
)
from schemas.facts import Facts


AST_READY = JsxTreeSitterHelper().is_ready()


AST_CASES = [
    (
        "interactive-element-a11y",
        InteractiveElementA11yRule,
        "resources/js/components/NavMenu.tsx",
        """
export function NavMenu() {
  return <button onClick={openMenu}>Open</button>;
}
""",
        """
export function Card() {
  return <div onClick={openMenu} role="button" onKeyDown={onKeyDown}>Open</div>;
}
""",
        """
export function Card() {
  return <div onClick={openMenu}>Open</div>;
}
""",
    ),
    (
        "form-label-association",
        FormLabelAssociationRule,
        "resources/js/components/forms/ProfileForm.tsx",
        """
export function ProfileForm() {
  return (
    <>
      <label htmlFor="email">Email</label>
      <input id="email" />
    </>
  );
}
""",
        """
export function ProfileForm() {
  return (
    <>
      <input id="email" aria-labelledby="email-label" />
      <label id="email-label">Email</label>
    </>
  );
}
""",
        """
export function ProfileForm() {
  return (
    <>
      <label>Email</label>
      <input id="email" />
    </>
  );
}
""",
    ),
    (
        "modal-trap-focus",
        ModalTrapFocusRule,
        "resources/js/components/modals/EditProfileModal.tsx",
        """
export function HelpPanel() {
  return <section>Help</section>;
}
""",
        """
export function EditProfileModal() {
  const onClose = () => setOpen(false);
  return (
    <DialogContent role="dialog" onKeyDown={onKeyDown}>
      <FocusTrap><input autoFocus /></FocusTrap>
    </DialogContent>
  );
}
""",
        """
export function EditProfileModal() {
  return (
    <DialogContent role="dialog">
      <input />
    </DialogContent>
  );
}
""",
    ),
    (
        "semantic-wrapper-breakage",
        SemanticWrapperBreakageRule,
        "resources/js/components/lists/InboxList.tsx",
        """
export function InboxList() {
  return (
    <ul>
      <li><span>One</span></li>
    </ul>
  );
}
""",
        """
export function InboxTable() {
  return (
    <table>
      <tbody>
        <tr><td>One</td></tr>
      </tbody>
    </table>
  );
}
""",
        """
export function InboxList() {
  return (
    <ul>
      <div>One</div>
    </ul>
  );
}
""",
    ),
    (
        "interactive-accessible-name-required",
        InteractiveAccessibleNameRequiredRule,
        "resources/js/components/buttons/IconButton.tsx",
        """
export function IconButton() {
  return <button aria-label="Close"><CloseIcon /></button>;
}
""",
        """
export function IconButton() {
  return <button>{t('actions.close')}</button>;
}
""",
        """
export function IconButton() {
  return <button><CloseIcon /></button>;
}
""",
    ),
    (
        "jsx-aria-attribute-format",
        JsxAriaAttributeFormatRule,
        "resources/js/components/buttons/IconButton.tsx",
        """
export function IconButton() {
  return <button aria-label="Close" aria-expanded={false}>Close</button>;
}
""",
        """
export function IconButton() {
  return <button aria-controls="menu">Menu</button>;
}
""",
        """
export function IconButton() {
  return <button ariaLabel="Close">Close</button>;
}
""",
    ),
    (
        "outside-click-without-keyboard-fallback",
        OutsideClickWithoutKeyboardFallbackRule,
        "resources/js/components/overlays/UserMenu.tsx",
        """
export function UserMenu() {
  return <div>Menu</div>;
}
""",
        """
export function UserMenu() {
  useEffect(() => {
    const handlePointer = (event) => {
      if (!containerRef.current?.contains(event.target)) setOpen(false);
    };
    const handleKey = (event) => {
      if (event.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', handlePointer);
    document.addEventListener('keydown', handleKey);
    return () => {
      document.removeEventListener('mousedown', handlePointer);
      document.removeEventListener('keydown', handleKey);
    };
  }, []);
}
""",
        """
export function UserMenu() {
  useEffect(() => {
    const handlePointer = (event) => {
      if (!containerRef.current?.contains(event.target)) setOpen(false);
    };
    document.addEventListener('mousedown', handlePointer);
    return () => document.removeEventListener('mousedown', handlePointer);
  }, []);
}
""",
    ),
    (
        "apg-tabs-keyboard-contract",
        APGTabsKeyboardContractRule,
        "resources/js/components/tabs/ProfileTabs.tsx",
        """
export function ProfileTabs() {
  return (
    <>
      <div role="tablist">
        <button role="tab" aria-selected={true} aria-controls="panel-a">A</button>
      </div>
      <div role="tabpanel" id="panel-a">Panel</div>
    </>
  );
}
""",
        """
export function ProfileTabs() {
  return (
    <>
      <div role="tablist">
        <button role="tab" aria-selected={true} aria-controls="panel-a">A</button>
      </div>
      <div role="tabpanel" id="panel-a">Panel</div>
    </>
  );
}
""",
        """
export function ProfileTabs() {
  return (
    <div>
      <button role="tab">A</button>
    </div>
  );
}
""",
    ),
    (
        "apg-accordion-disclosure-contract",
        APGAccordionDisclosureContractRule,
        "resources/js/components/accordion/FAQ.tsx",
        """
export function FAQ() {
  return <section>FAQ</section>;
}
""",
        """
export function FAQ() {
  return <button aria-expanded={false} aria-controls="faq-panel">Toggle</button>;
}
""",
        """
export function FAQ() {
  return <div aria-expanded={false}>Toggle</div>;
}
""",
    ),
    (
        "apg-menu-button-contract",
        APGMenuButtonContractRule,
        "resources/js/components/menu/UserMenu.tsx",
        """
export function UserMenu() {
  return (
    <>
      <button aria-haspopup="menu" aria-expanded={false} aria-controls="user-menu" onKeyDown={onKeyDown}>Open</button>
      <ul role="menu" id="user-menu"><li role="menuitem">Logout</li></ul>
    </>
  );
}
""",
        """
export function UserMenu() {
  return (
    <>
      <button aria-haspopup="menu" aria-expanded={false} aria-controls="user-menu" onKeyDown={onKeyDown}>Open</button>
      <ul role="menu" id="user-menu"><li role="menuitem">Logout</li></ul>
    </>
  );
}
""",
        """
export function UserMenu() {
  return <button aria-haspopup="menu">Open</button>;
}
""",
    ),
    (
        "apg-combobox-contract",
        APGComboboxContractRule,
        "resources/js/components/inputs/CityCombobox.tsx",
        """
export function CityCombobox() {
  return (
    <>
      <div role="combobox" aria-expanded={false} aria-controls="cities" aria-activedescendant="city-1" onKeyDown={onKeyDown} />
      <ul role="listbox" id="cities"><li id="city-1">Cairo</li></ul>
    </>
  );
}
""",
        """
export function CityCombobox() {
  return (
    <>
      <div role="combobox" aria-expanded={false} aria-controls="cities" aria-activedescendant="city-1" onKeyDown={onKeyDown} />
      <ul role="listbox" id="cities"><li id="city-1">Cairo</li></ul>
    </>
  );
}
""",
        """
export function CityCombobox() {
  return <div role="combobox" />;
}
""",
    ),
    (
        "dialog-focus-restore-missing",
        DialogFocusRestoreMissingRule,
        "resources/js/components/modals/DeleteModal.tsx",
        """
export function HelpPanel() {
  return <section>Help</section>;
}
""",
        """
export function DeleteModal() {
  return (
    <DialogContent role="dialog" onOpenChange={setOpen} onCloseAutoFocus={restoreFocus}>
      Confirm
    </DialogContent>
  );
}
""",
        """
export function DeleteModal() {
  return (
    <DialogContent role="dialog" onOpenChange={setOpen}>
      Confirm
    </DialogContent>
  );
}
""",
    ),
]


REGEX_CASES = [
    (
        "skip-link-missing",
        SkipLinkMissingRule,
        "resources/js/layouts/AppShell.tsx",
        """
export function AppShell() {
  return (
    <>
      <a href="#main" className="sr-only focus:not-sr-only">Skip</a>
      <main id="main">Body</main>
    </>
  );
}
""",
        """
export function AppShell() {
  return (
    <>
      <a href="#main" className="sr-only focus:not-sr-only">Skip</a>
      <main>Main</main>
    </>
  );
}
""",
        """
export function AppShell() {
  return (
    <>
      <header>Header</header>
      <main id="content">Body</main>
    </>
  );
}
""",
    ),
    (
        "focus-indicator-missing",
        FocusIndicatorMissingRule,
        "resources/js/components/buttons/ActionButton.tsx",
        """
export function ActionButton() {
  return <button className="px-3 py-2">Save</button>;
}
""",
        """
export function ActionButton() {
  return <button className="focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">Save</button>;
}
""",
        """
export function ActionButton() {
  return <button className="focus:outline-none">Save</button>;
}
""",
    ),
    (
        "touch-target-size",
        TouchTargetSizeRule,
        "resources/js/components/buttons/IconButton.tsx",
        """
export function IconButton() {
  return <button className="w-12 h-12">+</button>;
}
""",
        """
export function IconButton() {
  return <button className="w-11 h-11">+</button>;
}
""",
        """
export function IconButton() {
  return <button className="w-8 h-8">+</button>;
}
""",
    ),
    (
        "tailwind-motion-reduce-missing",
        TailwindMotionReduceMissingRule,
        "resources/js/pages/Dashboard.tsx",
        """
export function Dashboard() {
  return <div className="p-4">Dashboard</div>;
}
""",
        """
export function Dashboard() {
  return <div className="motion-safe:animate-spin">Spin</div>;
}
""",
        """
export function Dashboard() {
  return <div className="animate-spin">Spin</div>;
}
""",
    ),
    (
        "tailwind-appearance-none-risk",
        TailwindAppearanceNoneRiskRule,
        "resources/js/components/forms/Select.tsx",
        """
export function SelectInput() {
  return <select className="border px-3 py-2 focus-visible:ring-2"><option>A</option></select>;
}
""",
        """
export function SelectInput() {
  return <select className="appearance-none border px-3 py-2 focus-visible:ring-2"><option>A</option></select>;
}
""",
        """
export function SelectInput() {
  return <select className="appearance-none"><option>A</option></select>;
}
""",
    ),
    (
        "css-focus-outline-without-replacement",
        CssFocusOutlineWithoutReplacementRule,
        "resources/css/app.css",
        """
.btn { color: #111; }
""",
        """
.btn:focus {
  outline: none;
  box-shadow: 0 0 0 2px #2563eb;
}
""",
        """
.btn:focus {
  outline: none;
}
""",
    ),
    (
        "css-hover-only-interaction",
        CssHoverOnlyInteractionRule,
        "resources/css/app.css",
        """
.btn { color: #111; }
""",
        """
.btn:hover { color: #111; }
.btn:focus-visible { color: #111; }
""",
        """
.btn:hover { color: #111; }
""",
    ),
    (
        "css-color-only-state-indicator",
        CssColorOnlyStateIndicatorRule,
        "resources/css/app.css",
        """
.card { color: #111; }
""",
        """
.error {
  color: #b91c1c;
  font-weight: 700;
}
""",
        """
.error {
  color: #b91c1c;
  background: #fee2e2;
  border-color: #b91c1c;
}
""",
    ),
]


@pytest.mark.skipif(not AST_READY, reason="Tree-sitter JSX parser is unavailable")
@pytest.mark.parametrize("rule_id,rule_cls,file_path,valid,near,invalid", AST_CASES)
def test_wcag_apg_ast_rules_valid_near_invalid(
    rule_id: str,
    rule_cls,
    file_path: str,
    valid: str,
    near: str,
    invalid: str,
) -> None:
    rule = rule_cls(RuleConfig())
    facts = Facts(project_path=".")
    assert rule.analyze_ast(file_path, valid, facts) == []
    assert rule.analyze_ast(file_path, near, facts) == []
    findings = rule.analyze_ast(file_path, invalid, facts)
    assert findings, f"{rule_id} should fire on invalid sample"
    assert any(f.rule_id == rule_id for f in findings)


@pytest.mark.parametrize("rule_id,rule_cls,file_path,valid,near,invalid", REGEX_CASES)
def test_wcag_apg_regex_rules_valid_near_invalid(
    rule_id: str,
    rule_cls,
    file_path: str,
    valid: str,
    near: str,
    invalid: str,
) -> None:
    rule = rule_cls(RuleConfig())
    facts = Facts(project_path=".")
    assert rule.analyze_regex(file_path, valid, facts) == []
    assert rule.analyze_regex(file_path, near, facts) == []
    findings = rule.analyze_regex(file_path, invalid, facts)
    assert findings, f"{rule_id} should fire on invalid sample"
    assert any(f.rule_id == rule_id for f in findings)


@pytest.mark.skipif(not AST_READY, reason="Tree-sitter JSX parser is unavailable")
def test_decision_profile_evidence_for_pointer_only_overlay() -> None:
    rule = OutsideClickWithoutKeyboardFallbackRule(RuleConfig())
    facts = Facts(project_path=".")
    findings = rule.analyze_ast(
        "resources/js/components/overlays/UserMenu.tsx",
        """
export function UserMenu() {
  useEffect(() => {
    const handlePointer = (event) => {
      if (!containerRef.current?.contains(event.target)) setOpen(false);
    };
    document.addEventListener('mousedown', handlePointer);
    return () => document.removeEventListener('mousedown', handlePointer);
  }, []);
}
""",
        facts,
    )
    assert findings
    meta = findings[0].metadata or {}
    decision = meta.get("decision_profile", {})
    assert decision.get("interaction_mode") == "pointer_only"
    assert decision.get("keyboard_contract_missing") is True


@pytest.mark.skipif(not AST_READY, reason="Tree-sitter JSX parser is unavailable")
def test_interactive_accessible_name_accepts_dynamic_labeling_patterns() -> None:
    rule = InteractiveAccessibleNameRequiredRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export function Buttons({ children }) {
  return (
    <>
      <button>{t('admin.save')}</button>
      <button aria-label={t('actions.close')}><CloseIcon /></button>
      <button><span>{children}</span></button>
    </>
  );
}
"""
    assert rule.analyze_ast("resources/js/components/buttons/Buttons.tsx", content, facts) == []


@pytest.mark.skipif(not AST_READY, reason="Tree-sitter JSX parser is unavailable")
def test_dialog_focus_restore_rule_skips_headlessui_dialogs() -> None:
    rule = DialogFocusRestoreMissingRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
import { Dialog } from '@headlessui/react';

export function ConfirmDialog({ open, onClose }) {
  return (
    <Dialog open={open} onClose={onClose}>
      <Dialog.Panel>Confirm</Dialog.Panel>
    </Dialog>
  );
}
"""
    assert rule.analyze_ast("resources/js/components/modals/ConfirmDialog.tsx", content, facts) == []


@pytest.mark.skipif(not AST_READY, reason="Tree-sitter JSX parser is unavailable")
def test_custom_widget_rules_are_ast_based() -> None:
    assert APGTabsKeyboardContractRule.type == "ast"
    assert APGAccordionDisclosureContractRule.type == "ast"
    assert APGMenuButtonContractRule.type == "ast"
    assert APGComboboxContractRule.type == "ast"
    assert OutsideClickWithoutKeyboardFallbackRule.type == "ast"
    assert DialogFocusRestoreMissingRule.type == "ast"


def test_wcag_apg_rules_enabled_in_all_profiles() -> None:
    required_ids = {
        "interactive-element-a11y",
        "form-label-association",
        "modal-trap-focus",
        "skip-link-missing",
        "focus-indicator-missing",
        "touch-target-size",
        "semantic-wrapper-breakage",
        "interactive-accessible-name-required",
        "jsx-aria-attribute-format",
        "outside-click-without-keyboard-fallback",
        "apg-tabs-keyboard-contract",
        "apg-accordion-disclosure-contract",
        "apg-menu-button-contract",
        "apg-combobox-contract",
        "dialog-focus-restore-missing",
        "tailwind-motion-reduce-missing",
        "tailwind-appearance-none-risk",
        "css-focus-outline-without-replacement",
        "css-hover-only-interaction",
        "css-color-only-state-indicator",
    }
    backend_root = Path(__file__).resolve().parents[1]
    for profile_name in ("startup", "balanced", "strict"):
        ruleset = Ruleset.load(backend_root / "rulesets" / f"{profile_name}.yaml")
        for rule_id in required_ids:
            assert rule_id in ruleset.rules, f"{rule_id} missing in {profile_name}"
            assert ruleset.rules[rule_id].enabled is True


def test_wcag_apg_context_calibration_shifts_by_project_type_and_capability() -> None:
    matrix = ContextProfileMatrix.load_default()
    for rule_id in (
        "interactive-accessible-name-required",
        "outside-click-without-keyboard-fallback",
        "tailwind-motion-reduce-missing",
        "css-hover-only-interaction",
    ):
        assert rule_id in matrix.rule_behavior

    base_ctx = matrix.resolve_context(
        explicit_project_type="internal_admin_system",
        explicit_profile="layered",
    )
    realtime_ctx = matrix.resolve_context(
        explicit_project_type="realtime_game_control_platform",
        explicit_profile="layered",
    )
    public_portal_ctx = matrix.resolve_context(
        explicit_project_type="public_website_with_dashboard",
        explicit_profile="layered",
        explicit_capabilities={"multi_role_portal": True},
    )

    base_interactive = matrix.calibrate_rule("interactive-accessible-name-required", base_ctx)
    realtime_interactive = matrix.calibrate_rule("interactive-accessible-name-required", realtime_ctx)
    portal_interactive = matrix.calibrate_rule("interactive-accessible-name-required", public_portal_ctx)

    assert base_interactive.get("severity") == "high"
    assert realtime_interactive.get("severity") == "medium"
    assert portal_interactive.get("severity") == "high"

    base_css = matrix.calibrate_rule("css-hover-only-interaction", base_ctx)
    portal_css = matrix.calibrate_rule("css-hover-only-interaction", public_portal_ctx)
    assert base_css.get("severity") in {"low", "medium"}
    assert portal_css.get("severity") == "medium"
