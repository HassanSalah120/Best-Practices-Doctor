"""
React Form Label Association Rule (hardened, AST-first).
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule
from rules.react.jsx_tree_sitter import JsxTreeSitterHelper


class FormLabelAssociationRule(Rule):
    id = "form-label-association"
    name = "Form Label Association"
    description = "Detects labels that are not associated with a form control"
    category = Category.ACCESSIBILITY
    default_severity = Severity.HIGH
    type = "ast"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _CONTROL_TAGS = {"input", "select", "textarea"}
    _ALLOWLIST_PATH_MARKERS = (
        "/tests/",
        "/test/",
        "/__tests__/",
        "/stories/",
        "/storybook/",
        "/demo/",
        "/demos/",
        "/fixtures/",
        "/generated/",
        "/dist/",
        "/build/",
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

    def analyze_ast(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._is_allowlisted_path(file_path):
            return []
        if not self._jsx.is_ready():
            return []
        if "<label" not in (content or "").lower():
            return []

        tree = self._jsx.parse_tree(file_path, content or "")
        if not tree or not getattr(tree, "root_node", None):
            return []

        content_bytes = (content or "").encode("utf-8")
        aria_labelledby_values = self._collect_aria_labelledby(tree.root_node, content_bytes)
        findings: list[Finding] = []
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 3)))

        for node in self._jsx.iter_jsx_elements(tree.root_node):
            if len(findings) >= max_findings:
                break
            opening = self._jsx.get_opening_node(node)
            tag = self._jsx.get_tag_name(opening, content_bytes).lower()
            if tag != "label":
                continue

            attrs = self._jsx.get_attributes(opening, content_bytes)
            attr_map = {a.name: a for a in attrs}
            has_html_for = "htmlFor" in attr_map or "for" in attr_map
            if has_html_for:
                continue
            if self._has_nested_form_control(node, content_bytes):
                continue
            if self._contains_custom_form_wrapper(node, content_bytes):
                continue
            if self._is_referenced_by_aria_labelledby(attr_map, aria_labelledby_values):
                continue
            if not self._has_readable_label_text(node, content_bytes):
                continue

            line = node.start_point.row + 1
            findings.append(
                self.create_finding(
                    title="Form label may not be associated with a control",
                    context=f"{file_path}:{line}:label-association",
                    file=file_path,
                    line_start=line,
                    description=(
                        "Found a `<label>` without `htmlFor`, without nested native control, and without "
                        "`aria-labelledby` linkage evidence."
                    ),
                    why_it_matters=(
                        "Screen readers rely on explicit label association to announce field purpose consistently."
                    ),
                    suggested_fix=(
                        "Associate labels via `htmlFor` + matching control `id`, or wrap the control inside the label."
                    ),
                    tags=["react", "a11y", "forms", "wcag"],
                    confidence=0.9,
                    evidence_signals=[
                        "label_missing_htmlfor=true",
                        "embedded_control_missing=true",
                        "aria_labelledby_link_missing=true",
                    ],
                )
            )

        return findings

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        # Backward-compatible alias for older tests/callers that still invoke analyze_regex directly.
        findings = self.analyze_ast(file_path, content, facts, metrics)
        if findings and self._has_simple_aria_labelledby_pair(content or ""):
            return []
        return findings

    def _collect_aria_labelledby(self, root, content_bytes: bytes) -> set[str]:
        values: set[str] = set()
        for node in self._jsx.iter_jsx_elements(root):
            opening = self._jsx.get_opening_node(node)
            for attr in self._jsx.get_attributes(opening, content_bytes):
                if attr.name != "aria-labelledby":
                    continue
                val = self._attr_text(attr)
                if val:
                    values.update(part.strip() for part in val.split() if part.strip())
        return values

    def _has_nested_form_control(self, label_node, content_bytes: bytes) -> bool:
        if label_node.type != "jsx_element":
            return False
        for child in self._jsx.walk(label_node):
            if child is label_node:
                continue
            if child.type not in {"jsx_element", "jsx_self_closing_element"}:
                continue
            opening = self._jsx.get_opening_node(child)
            tag = self._jsx.get_tag_name(opening, content_bytes).lower()
            if tag in self._CONTROL_TAGS:
                return True
        return False

    def _contains_custom_form_wrapper(self, label_node, content_bytes: bytes) -> bool:
        if label_node.type != "jsx_element":
            return False
        for child in self._jsx.walk(label_node):
            if child is label_node:
                continue
            if child.type not in {"jsx_element", "jsx_self_closing_element"}:
                continue
            opening = self._jsx.get_opening_node(child)
            tag = self._jsx.get_tag_name(opening, content_bytes).strip()
            if tag and tag[0].isupper():
                return True
        return False

    def _is_referenced_by_aria_labelledby(self, attr_map: dict[str, object], aria_labelledby_values: set[str]) -> bool:
        id_attr = attr_map.get("id")
        if id_attr is None:
            return False
        label_id = self._attr_text(id_attr)
        if not label_id:
            return False
        return label_id in aria_labelledby_values

    def _attr_text(self, attr: object) -> str:
        static_value = str(getattr(attr, "static_value", "") or "").strip()
        if static_value:
            return static_value
        raw_value = str(getattr(attr, "raw_value", "") or "").strip()
        if raw_value.startswith("{") and raw_value.endswith("}"):
            raw_value = raw_value[1:-1].strip()
        if len(raw_value) >= 2 and raw_value[0] == raw_value[-1] and raw_value[0] in {"'", '"', "`"}:
            raw_value = raw_value[1:-1]
        return raw_value.strip()

    def _has_readable_label_text(self, label_node, content_bytes: bytes) -> bool:
        if label_node.type != "jsx_element":
            return False
        for child in getattr(label_node, "children", []) or []:
            if child.type != "jsx_text":
                continue
            text = content_bytes[child.start_byte : child.end_byte].decode("utf-8", errors="replace")
            if re.search(r"[A-Za-z0-9]", text or ""):
                return True
        return False

    def _has_simple_aria_labelledby_pair(self, content: str) -> bool:
        labels = re.findall(r"<label\b[^>]*\bid=['\"]([A-Za-z0-9\-_:.]+)['\"][^>]*>", content, flags=re.IGNORECASE)
        if not labels:
            return False
        referenced = set(
            part.strip()
            for raw in re.findall(r"aria-labelledby=['\"]([^'\"]+)['\"]", content, flags=re.IGNORECASE)
            for part in raw.split()
            if part.strip()
        )
        return any(label_id in referenced for label_id in labels)

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATH_MARKERS)
