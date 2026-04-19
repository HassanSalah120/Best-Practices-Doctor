"""
WCAG/APG React accessibility rules (AST-first).
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Category, Finding, Severity
from rules.base import Rule
from rules.react.jsx_tree_sitter import JsxAttributeInfo, JsxTreeSitterHelper


class _WcagAstRuleBase(Rule):
    type = "ast"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]
    _ALLOWLIST_PATHS = (
        "/tests/",
        "/test/",
        "/__tests__/",
        "/stories/",
        "/storybook/",
        "/fixtures/",
    )

    def __init__(self, config):
        super().__init__(config)
        self._jsx = JsxTreeSitterHelper()

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        return []

    def _skip_file(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS) or not self._jsx.is_ready()

    def _content_bytes(self, content: str) -> bytes:
        return (content or "").encode("utf-8")

    def _attr_map(self, attrs: list[JsxAttributeInfo]) -> dict[str, JsxAttributeInfo]:
        return {a.name: a for a in attrs}

    def _attr_value(self, attrs: dict[str, JsxAttributeInfo], key: str) -> str:
        attr = attrs.get(key)
        if not attr:
            return ""
        return str(attr.static_value or "").strip()

    def _has_attr(self, attrs: dict[str, JsxAttributeInfo], key: str) -> bool:
        return key in attrs

    def _has_keyboard_signal(self, attrs: dict[str, JsxAttributeInfo], text: str) -> bool:
        return any(k in attrs for k in ("onKeyDown", "onKeyUp", "onKeyPress")) or bool(
            re.search(r"Arrow(?:Up|Down|Left|Right)|Home|End|Escape", text or "")
        )


class SemanticWrapperBreakageRule(_WcagAstRuleBase):
    id = "semantic-wrapper-breakage"
    name = "Semantic Wrapper Breakage"
    description = "Detects JSX wrappers that break list/table/description-list semantics"
    category = Category.ACCESSIBILITY
    default_severity = Severity.MEDIUM

    _BAD_DIRECT = {"div", "span", "section", "article", "p"}
    _LIST_CONTAINERS = {"ul", "ol"}
    _TABLE_CONTAINERS = {"table"}
    _ROW_GROUP_CONTAINERS = {"thead", "tbody", "tfoot"}

    def analyze_ast(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        tree = self._jsx.parse_tree(file_path, content or "")
        if not tree or not getattr(tree, "root_node", None):
            return []

        findings: list[Finding] = []
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 3)))
        cb = self._content_bytes(content or "")

        for parent in self._jsx.iter_jsx_elements(tree.root_node):
            if len(findings) >= max_findings:
                break
            parent_open = self._jsx.get_opening_node(parent)
            parent_tag = self._jsx.get_tag_name(parent_open, cb).lower()
            if parent_tag not in self._LIST_CONTAINERS | self._TABLE_CONTAINERS | self._ROW_GROUP_CONTAINERS | {"tr", "dl"}:
                continue

            for child in self._jsx.direct_child_elements(parent):
                child_open = self._jsx.get_opening_node(child)
                child_tag = self._jsx.get_tag_name(child_open, cb).lower()
                if not child_tag:
                    continue
                if self._is_valid_child(parent_tag, child_tag):
                    continue
                if child_tag[0].isupper():
                    continue

                line = child.start_point.row + 1
                findings.append(
                    self.create_finding(
                        title="Wrapper element may break native semantics",
                        context=f"{file_path}:{line}:{parent_tag}>{child_tag}",
                        file=file_path,
                        line_start=line,
                        description=f"Found `{child_tag}` as direct child of `{parent_tag}` which can break native semantics.",
                        why_it_matters="Screen readers and keyboard navigation rely on valid native list/table/description semantics.",
                        suggested_fix="Use valid semantic children (`li`, `tr`, `td/th`, `dt/dd`) or move wrappers outside the semantic container.",
                        tags=["a11y", "wcag", "semantics", "html"],
                        confidence=0.92,
                        evidence_signals=[f"parent_tag={parent_tag}", f"child_tag={child_tag}"],
                        metadata={
                            "decision_profile": {
                                "widget_type": "semantic_container",
                                "missing_apg_signals": f"invalid_child:{parent_tag}>{child_tag}",
                            }
                        },
                    )
                )
                if len(findings) >= max_findings:
                    break
        return findings

    def _is_valid_child(self, parent_tag: str, child_tag: str) -> bool:
        if parent_tag in self._LIST_CONTAINERS:
            return child_tag in {"li", "template", "script"}
        if parent_tag == "table":
            return child_tag in {"caption", "colgroup", "thead", "tbody", "tfoot", "tr"}
        if parent_tag in self._ROW_GROUP_CONTAINERS:
            return child_tag == "tr"
        if parent_tag == "tr":
            return child_tag in {"td", "th"}
        if parent_tag == "dl":
            return child_tag in {"dt", "dd", "div"}
        return True


class InteractiveAccessibleNameRequiredRule(_WcagAstRuleBase):
    id = "interactive-accessible-name-required"
    name = "Interactive Accessible Name Required"
    description = "Detects interactive controls that lack a programmatic accessible name"
    category = Category.ACCESSIBILITY
    default_severity = Severity.HIGH

    _NATIVE_INTERACTIVE = {"button", "a", "summary"}
    _ROLE_INTERACTIVE = {"button", "tab", "switch", "menuitem", "combobox", "option"}

    def analyze_ast(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        tree = self._jsx.parse_tree(file_path, content or "")
        if not tree or not getattr(tree, "root_node", None):
            return []

        findings: list[Finding] = []
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 4)))
        cb = self._content_bytes(content or "")

        for node in self._jsx.iter_jsx_elements(tree.root_node):
            if len(findings) >= max_findings:
                break
            opening = self._jsx.get_opening_node(node)
            tag = self._jsx.get_tag_name(opening, cb).strip()
            attrs = self._attr_map(self._jsx.get_attributes(opening, cb))
            role = self._attr_value(attrs, "role").lower()
            is_interactive = tag.lower() in self._NATIVE_INTERACTIVE or role in self._ROLE_INTERACTIVE
            if not is_interactive:
                continue
            if tag.lower() == "a" and not (self._has_attr(attrs, "href") or self._has_attr(attrs, "onClick")):
                continue
            if self._has_true(attrs, "aria-hidden"):
                continue

            source = self._accessible_name_source(node, attrs, cb)
            if source != "missing":
                continue

            line = node.start_point.row + 1
            findings.append(
                self.create_finding(
                    title="Interactive control is missing an accessible name",
                    context=f"{file_path}:{line}:{tag.lower()}",
                    file=file_path,
                    line_start=line,
                    description="Interactive element does not expose an accessible label via text, aria-label, or aria-labelledby.",
                    why_it_matters="Controls without accessible names are hard or impossible to use with screen readers.",
                    suggested_fix="Add visible text or provide `aria-label` / `aria-labelledby` for icon-only and custom controls.",
                    tags=["a11y", "wcag", "aria", "forms"],
                    confidence=0.9,
                    evidence_signals=[
                        f"tag={tag.lower()}",
                        "accessible_name_source=missing",
                    ],
                    metadata={
                        "decision_profile": {
                            "widget_type": "interactive_control",
                            "accessible_name_source": "missing",
                        }
                    },
                )
            )
        return findings

    def _accessible_name_source(self, node, attrs: dict[str, JsxAttributeInfo], content_bytes: bytes) -> str:
        # Treat dynamic aria-label/aria-labelledby as valid names to avoid policy-noise on translated labels.
        if self._has_attr(attrs, "aria-label"):
            return "aria-label"
        if self._has_attr(attrs, "aria-labelledby"):
            return "aria-labelledby"
        if self._attr_value(attrs, "title"):
            return "title"
        if self._visible_text(node, content_bytes):
            return "visible-text"
        return "missing"

    def _visible_text(self, node, content_bytes: bytes) -> bool:
        return self._node_contains_accessible_text(node, content_bytes)

    def _node_contains_accessible_text(self, node, content_bytes: bytes) -> bool:
        if not node:
            return False

        if node.type in {"jsx_element", "jsx_self_closing_element"}:
            opening = self._jsx.get_opening_node(node)
            attrs = self._attr_map(self._jsx.get_attributes(opening, content_bytes))
            if self._has_true(attrs, "aria-hidden"):
                return False

        if node.type == "jsx_text":
            text = content_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
            if re.search(r"[A-Za-z0-9]", text or ""):
                return True

        if node.type == "jsx_expression":
            expr = content_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
            if self._expression_may_render_text(expr):
                return True

        for child in getattr(node, "children", []) or []:
            if self._node_contains_accessible_text(child, content_bytes):
                return True
        return False

    def _expression_may_render_text(self, expr: str) -> bool:
        raw = (expr or "").strip()
        if not raw:
            return False
        inner = raw
        if raw.startswith("{") and raw.endswith("}"):
            inner = raw[1:-1].strip()
        if not inner or inner in {"null", "undefined", "false", "true"}:
            return False
        if inner.startswith("<") and inner.endswith(">"):
            return False
        if re.search(r"\b(?:t|translate|i18n\.t)\s*\(", inner):
            return True
        if re.search(r"['\"`][^'\"`]+['\"`]", inner):
            return True
        if re.fullmatch(r"[-+*/%0-9().\s]+", inner):
            return False
        return bool(re.search(r"[A-Za-z_]", inner))

    def _has_true(self, attrs: dict[str, JsxAttributeInfo], key: str) -> bool:
        val = self._attr_value(attrs, key).lower()
        raw = (attrs.get(key).raw_value if attrs.get(key) else "").lower()
        return val == "true" or raw in {"{true}", '"true"', "'true'"}


class JsxAriaAttributeFormatRule(_WcagAstRuleBase):
    id = "jsx-aria-attribute-format"
    name = "JSX ARIA Attribute Format"
    description = "Detects malformed ARIA attribute names in JSX"
    category = Category.ACCESSIBILITY
    default_severity = Severity.MEDIUM

    _VALID_ARIA_RE = re.compile(r"^aria-[a-z0-9\-]+$")

    def analyze_ast(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        tree = self._jsx.parse_tree(file_path, content or "")
        if not tree or not getattr(tree, "root_node", None):
            return []

        findings: list[Finding] = []
        cb = self._content_bytes(content or "")
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 5)))

        for node in self._jsx.iter_jsx_elements(tree.root_node):
            if len(findings) >= max_findings:
                break
            opening = self._jsx.get_opening_node(node)
            attrs = self._jsx.get_attributes(opening, cb)
            for attr in attrs:
                name = attr.name or ""
                low = name.lower()
                if not low.startswith("aria"):
                    continue
                malformed = False
                reason = ""
                if low.startswith("aria-"):
                    if name != low or not self._VALID_ARIA_RE.match(low):
                        malformed = True
                        reason = "invalid_aria_token"
                else:
                    malformed = True
                    reason = "missing_aria_hyphen"
                if not malformed:
                    continue
                findings.append(
                    self.create_finding(
                        title="Malformed ARIA attribute in JSX",
                        context=f"{file_path}:{attr.line}:{name}",
                        file=file_path,
                        line_start=attr.line,
                        description=f"`{name}` is not a valid JSX ARIA attribute format.",
                        why_it_matters="Malformed ARIA attributes are ignored by assistive technologies and can silently break accessibility.",
                        suggested_fix="Use lowercase hyphenated ARIA attributes (for example `aria-label`, `aria-expanded`, `aria-controls`).",
                        tags=["a11y", "aria", "jsx"],
                        confidence=0.96,
                        evidence_signals=[f"attribute={name}", f"reason={reason}"],
                        metadata={
                            "decision_profile": {
                                "widget_type": "aria_attribute",
                                "missing_apg_signals": reason,
                            }
                        },
                    )
                )
                if len(findings) >= max_findings:
                    break
        return findings


class OutsideClickWithoutKeyboardFallbackRule(_WcagAstRuleBase):
    id = "outside-click-without-keyboard-fallback"
    name = "Outside Click Without Keyboard Fallback"
    description = "Detects outside-click close logic without keyboard fallback"
    category = Category.ACCESSIBILITY
    default_severity = Severity.HIGH

    def analyze_ast(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        if not self._jsx.is_ready():
            return []

        text = content or ""
        pointer_close = bool(re.search(r"addEventListener\(\s*['\"](?:mousedown|click|pointerdown)['\"]", text))
        outside_logic = bool(re.search(r"outside|contains\(\s*event\.target|target\s*!=", text, flags=re.IGNORECASE))
        keyboard_close = bool(re.search(r"Escape|Esc|onKeyDown|addEventListener\(\s*['\"]keydown['\"]", text))
        if not pointer_close or not outside_logic or keyboard_close:
            return []

        return [
            self.create_finding(
                title="Outside-click close behavior lacks keyboard fallback",
                context=f"{file_path}:outside-click-keyboard",
                file=file_path,
                line_start=1,
                description="Detected pointer-based outside-click close handling without an equivalent keyboard close path.",
                why_it_matters="Pointer-only dismissal blocks keyboard users and violates expected APG interaction patterns for overlays.",
                suggested_fix="Add keyboard dismissal support (Escape/onKeyDown) and ensure focus is managed when the overlay closes.",
                tags=["a11y", "wcag", "apg", "keyboard", "overlay"],
                confidence=0.88,
                evidence_signals=[
                    "interaction_mode=pointer_only",
                    "keyboard_contract_missing=true",
                ],
                metadata={"decision_profile": {"interaction_mode": "pointer_only", "keyboard_contract_missing": True}},
            )
        ]


class APGTabsKeyboardContractRule(_WcagAstRuleBase):
    id = "apg-tabs-keyboard-contract"
    name = "APG Tabs Keyboard Contract"
    description = "Detects custom tab widgets missing APG role/state/keyboard signals"
    category = Category.ACCESSIBILITY
    default_severity = Severity.HIGH

    def analyze_ast(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return self._analyze_widget(file_path, content, "tabs")

    def _analyze_widget(self, file_path: str, content: str, widget_type: str) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        tree = self._jsx.parse_tree(file_path, content or "")
        if not tree or not getattr(tree, "root_node", None):
            return []
        text = content or ""
        cb = self._content_bytes(text)

        has_tablist = False
        has_tab = False
        has_tabpanel = False
        has_selected = False
        has_controls = False
        has_keyboard = False

        for node in self._jsx.iter_jsx_elements(tree.root_node):
            opening = self._jsx.get_opening_node(node)
            attrs = self._attr_map(self._jsx.get_attributes(opening, cb))
            role = self._attr_value(attrs, "role").lower()
            if role == "tablist":
                has_tablist = True
                has_keyboard = has_keyboard or self._has_keyboard_signal(attrs, text)
            if role == "tab":
                has_tab = True
                if self._has_attr(attrs, "aria-selected"):
                    has_selected = True
                if self._has_attr(attrs, "aria-controls"):
                    has_controls = True
                has_keyboard = has_keyboard or self._has_keyboard_signal(attrs, text)
            if role == "tabpanel":
                has_tabpanel = True

        if not (has_tablist or has_tab):
            return []

        missing = []
        if not has_tablist:
            missing.append("role=tablist")
        if not has_tab:
            missing.append("role=tab")
        if not has_tabpanel:
            missing.append("role=tabpanel")
        if not has_selected:
            missing.append("aria-selected")
        if not has_controls:
            missing.append("aria-controls")
        if not has_keyboard:
            missing.append("arrow-key keyboard handling")

        if len(missing) < 2:
            return []
        return [
            self.create_finding(
                title="Custom tabs widget misses APG contract signals",
                context=f"{file_path}:tabs-apg",
                file=file_path,
                line_start=1,
                description=f"Tabs-like widget is missing APG signals: {', '.join(missing)}.",
                why_it_matters="APG tabs pattern depends on role/state mapping and keyboard behavior for assistive technology interoperability.",
                suggested_fix="Implement APG tabs contract: tablist/tab/tabpanel roles, selected+controls state, and arrow-key navigation.",
                tags=["a11y", "apg", "tabs", "keyboard"],
                confidence=0.9,
                evidence_signals=[
                    "widget_type=tabs",
                    f"missing_apg_signals={','.join(missing)}",
                    f"keyboard_contract_missing={int(not has_keyboard)}",
                ],
                metadata={
                    "decision_profile": {
                        "widget_type": "tabs",
                        "missing_apg_signals": ",".join(missing),
                        "keyboard_contract_missing": bool(not has_keyboard),
                    }
                },
            )
        ]


class APGAccordionDisclosureContractRule(_WcagAstRuleBase):
    id = "apg-accordion-disclosure-contract"
    name = "APG Accordion/Disclosure Contract"
    description = "Detects disclosure widgets missing APG button/expanded/controls signals"
    category = Category.ACCESSIBILITY
    default_severity = Severity.MEDIUM

    def analyze_ast(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        tree = self._jsx.parse_tree(file_path, content or "")
        if not tree or not getattr(tree, "root_node", None):
            return []

        cb = self._content_bytes(content or "")
        candidates = []
        for node in self._jsx.iter_jsx_elements(tree.root_node):
            opening = self._jsx.get_opening_node(node)
            tag = self._jsx.get_tag_name(opening, cb).lower()
            attrs = self._attr_map(self._jsx.get_attributes(opening, cb))
            if not self._has_attr(attrs, "aria-expanded"):
                continue
            candidates.append((node, tag, attrs))

        if not candidates:
            return []

        findings: list[Finding] = []
        for node, tag, attrs in candidates[:2]:
            missing = []
            role = self._attr_value(attrs, "role").lower()
            if tag != "button" and role != "button":
                missing.append("semantic button trigger")
            if not self._has_attr(attrs, "aria-controls"):
                missing.append("aria-controls")
            if tag != "button" and not self._has_keyboard_signal(attrs, content or ""):
                missing.append("keyboard toggle handling")
            if not missing:
                continue
            line = node.start_point.row + 1
            findings.append(
                self.create_finding(
                    title="Disclosure/accordion trigger misses APG contract signals",
                    context=f"{file_path}:{line}:accordion-apg",
                    file=file_path,
                    line_start=line,
                    description=f"Disclosure trigger is missing: {', '.join(missing)}.",
                    why_it_matters="APG disclosure patterns rely on button semantics, expanded state, controls linkage, and keyboard interaction.",
                    suggested_fix="Use a native button trigger with `aria-expanded` + `aria-controls`, and ensure keyboard toggle behavior.",
                    tags=["a11y", "apg", "accordion", "disclosure"],
                    confidence=0.88,
                    evidence_signals=[
                        "widget_type=accordion",
                        f"missing_apg_signals={','.join(missing)}",
                    ],
                    metadata={
                        "decision_profile": {
                            "widget_type": "accordion",
                            "missing_apg_signals": ",".join(missing),
                            "keyboard_contract_missing": "keyboard toggle handling" in missing,
                        }
                    },
                )
            )
        return findings


class APGMenuButtonContractRule(_WcagAstRuleBase):
    id = "apg-menu-button-contract"
    name = "APG Menu Button Contract"
    description = "Detects menu button widgets missing APG trigger/menu/keyboard signals"
    category = Category.ACCESSIBILITY
    default_severity = Severity.HIGH

    def analyze_ast(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        tree = self._jsx.parse_tree(file_path, content or "")
        if not tree or not getattr(tree, "root_node", None):
            return []
        text = content or ""
        cb = self._content_bytes(text)

        has_trigger = False
        has_expanded = False
        has_controls = False
        has_menu_role = False
        has_keyboard = bool(re.search(r"Escape|ArrowDown|ArrowUp", text))

        for node in self._jsx.iter_jsx_elements(tree.root_node):
            opening = self._jsx.get_opening_node(node)
            attrs = self._attr_map(self._jsx.get_attributes(opening, cb))
            haspopup = self._attr_value(attrs, "aria-haspopup").lower()
            role = self._attr_value(attrs, "role").lower()
            if haspopup == "menu" or role == "menuitem":
                has_trigger = True
                has_expanded = has_expanded or self._has_attr(attrs, "aria-expanded")
                has_controls = has_controls or self._has_attr(attrs, "aria-controls")
                has_keyboard = has_keyboard or self._has_keyboard_signal(attrs, text)
            if role == "menu":
                has_menu_role = True

        if not has_trigger:
            return []
        missing = []
        if not has_expanded:
            missing.append("aria-expanded")
        if not has_controls:
            missing.append("aria-controls")
        if not has_menu_role:
            missing.append("role=menu")
        if not has_keyboard:
            missing.append("menu keyboard handling")
        if len(missing) < 2:
            return []

        return [
            self.create_finding(
                title="Menu button widget misses APG contract signals",
                context=f"{file_path}:menu-apg",
                file=file_path,
                line_start=1,
                description=f"Menu button pattern is missing: {', '.join(missing)}.",
                why_it_matters="APG menu button interactions require explicit expanded/controls state and keyboard support.",
                suggested_fix="Implement APG menu button contract: trigger with haspopup/expanded/controls, menu role, and Escape/arrow key behavior.",
                tags=["a11y", "apg", "menu", "keyboard"],
                confidence=0.9,
                evidence_signals=["widget_type=menu-button", f"missing_apg_signals={','.join(missing)}"],
                metadata={
                    "decision_profile": {
                        "widget_type": "menu-button",
                        "missing_apg_signals": ",".join(missing),
                        "keyboard_contract_missing": "menu keyboard handling" in missing,
                    }
                },
            )
        ]


class APGComboboxContractRule(_WcagAstRuleBase):
    id = "apg-combobox-contract"
    name = "APG Combobox Contract"
    description = "Detects combobox widgets missing APG expanded/controls/active-option/keyboard signals"
    category = Category.ACCESSIBILITY
    default_severity = Severity.HIGH

    def analyze_ast(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        tree = self._jsx.parse_tree(file_path, content or "")
        if not tree or not getattr(tree, "root_node", None):
            return []
        text = content or ""
        cb = self._content_bytes(text)

        has_combobox = False
        has_expanded = False
        has_controls = False
        has_active_descendant = False
        has_listbox = False
        has_keyboard = bool(re.search(r"ArrowDown|ArrowUp|Enter|Escape", text))

        for node in self._jsx.iter_jsx_elements(tree.root_node):
            opening = self._jsx.get_opening_node(node)
            attrs = self._attr_map(self._jsx.get_attributes(opening, cb))
            role = self._attr_value(attrs, "role").lower()
            if role == "combobox":
                has_combobox = True
                has_expanded = has_expanded or self._has_attr(attrs, "aria-expanded")
                has_controls = has_controls or self._has_attr(attrs, "aria-controls")
                has_active_descendant = has_active_descendant or self._has_attr(attrs, "aria-activedescendant")
                has_keyboard = has_keyboard or self._has_keyboard_signal(attrs, text)
            if role == "listbox":
                has_listbox = True

        if not has_combobox:
            return []

        missing = []
        if not has_expanded:
            missing.append("aria-expanded")
        if not has_controls:
            missing.append("aria-controls")
        if not (has_active_descendant or has_listbox):
            missing.append("active option linkage")
        if not has_keyboard:
            missing.append("combobox keyboard handling")
        if len(missing) < 2:
            return []

        return [
            self.create_finding(
                title="Combobox widget misses APG contract signals",
                context=f"{file_path}:combobox-apg",
                file=file_path,
                line_start=1,
                description=f"Combobox pattern is missing: {', '.join(missing)}.",
                why_it_matters="APG combobox pattern requires explicit expanded/controls semantics and keyboard navigation signals.",
                suggested_fix="Implement APG combobox semantics (`role=combobox`, expanded/controls, active option linkage) plus arrow/escape handling.",
                tags=["a11y", "apg", "combobox", "keyboard"],
                confidence=0.9,
                evidence_signals=["widget_type=combobox", f"missing_apg_signals={','.join(missing)}"],
                metadata={
                    "decision_profile": {
                        "widget_type": "combobox",
                        "missing_apg_signals": ",".join(missing),
                        "keyboard_contract_missing": "combobox keyboard handling" in missing,
                    }
                },
            )
        ]


class DialogFocusRestoreMissingRule(_WcagAstRuleBase):
    id = "dialog-focus-restore-missing"
    name = "Dialog Focus Restore Missing"
    description = "Detects dialog/overlay flows missing focus restoration signals on close"
    category = Category.ACCESSIBILITY
    default_severity = Severity.HIGH

    _DIALOG_HINTS = ("Dialog", "Modal", "AlertDialog")
    _RESTORE_SIGNALS = (
        "onCloseAutoFocus",
        "returnFocus",
        "restoreFocus",
        "previousActiveElement",
        "triggerRef.current.focus",
        "focusTrigger",
    )
    _CLOSE_SIGNALS = ("onClose", "onOpenChange", "onDismiss", "setOpen(false)")
    _AUTO_RESTORE_LIBRARIES = (
        "@headlessui/react",
        "@radix-ui/react-dialog",
        "react-aria-components",
        "@react-aria/overlays",
    )

    def analyze_ast(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        tree = self._jsx.parse_tree(file_path, content or "")
        if not tree or not getattr(tree, "root_node", None):
            return []
        text = content or ""
        cb = self._content_bytes(text)

        has_dialog = False
        for node in self._jsx.iter_jsx_elements(tree.root_node):
            opening = self._jsx.get_opening_node(node)
            tag = self._jsx.get_tag_name(opening, cb)
            attrs = self._attr_map(self._jsx.get_attributes(opening, cb))
            role = self._attr_value(attrs, "role").lower()
            if any(tag.endswith(h) for h in self._DIALOG_HINTS) or role in {"dialog", "alertdialog"}:
                has_dialog = True
                break
        if not has_dialog:
            return []

        if self._has_auto_restore_library(text):
            return []

        has_close = any(s in text for s in self._CLOSE_SIGNALS) or bool(re.search(r"Escape|Esc", text))
        has_restore = any(s in text for s in self._RESTORE_SIGNALS)
        if not has_close or has_restore:
            return []

        return [
            self.create_finding(
                title="Dialog close flow may not restore focus to trigger",
                context=f"{file_path}:dialog-focus-restore",
                file=file_path,
                line_start=1,
                description="Dialog close signals exist, but no focus restoration signal was found.",
                why_it_matters="After closing dialogs, focus should return to a logical trigger target to preserve keyboard context.",
                suggested_fix="Store trigger reference and restore focus on close (or use a dialog primitive that restores focus automatically).",
                tags=["a11y", "wcag", "apg", "dialog", "focus"],
                confidence=0.87,
                evidence_signals=[
                    "widget_type=dialog",
                    "focus_restore_signal=0",
                    "keyboard_contract_missing=false",
                ],
                metadata={
                    "decision_profile": {
                        "widget_type": "dialog",
                        "focus_restore_signal": False,
                    }
                },
            )
        ]

    def _has_auto_restore_library(self, text: str) -> bool:
        low = (text or "").lower()
        return any(lib in low for lib in self._AUTO_RESTORE_LIBRARIES)
