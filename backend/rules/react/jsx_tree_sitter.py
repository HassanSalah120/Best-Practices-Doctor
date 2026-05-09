"""
Shared Tree-sitter JSX utilities for React accessibility rules.
"""

from __future__ import annotations

from dataclasses import dataclass

try:
    import tree_sitter_javascript as tsjs
    import tree_sitter_typescript as tsts
    from tree_sitter import Language, Parser

    TREE_SITTER_READY = True
except Exception:
    Language = None  # type: ignore[assignment]
    Parser = None  # type: ignore[assignment]
    TREE_SITTER_READY = False


@dataclass(frozen=True)
class JsxAttributeInfo:
    name: str
    raw_value: str
    static_value: str | None
    line: int

    @property
    def is_boolean(self) -> bool:
        return self.raw_value == ""

    @property
    def is_dynamic(self) -> bool:
        return self.raw_value.startswith("{") and self.static_value is None


class JsxTreeSitterHelper:
    def __init__(self) -> None:
        self._parsers: dict[str, Parser] = {}
        if TREE_SITTER_READY:
            try:
                self._parsers["javascript"] = Parser(Language(tsjs.language()))
                self._parsers["typescript"] = Parser(Language(tsts.language_typescript()))
                self._parsers["tsx"] = Parser(Language(tsts.language_tsx()))
            except Exception:
                self._parsers = {}

    def is_ready(self) -> bool:
        return bool(self._parsers)

    def parse_tree(self, file_path: str, content: str):
        parser = self._parsers.get(self._language_for(file_path))
        if not parser:
            return None
        try:
            return parser.parse((content or "").encode("utf-8"))
        except Exception:
            return None

    def walk(self, node):
        yield node
        for child in getattr(node, "children", []) or []:
            yield from self.walk(child)

    def iter_jsx_elements(self, root):
        for node in self.walk(root):
            if node.type in {"jsx_element", "jsx_self_closing_element"}:
                yield node

    def get_opening_node(self, jsx_node):
        if not jsx_node:
            return None
        if jsx_node.type == "jsx_self_closing_element":
            return jsx_node
        if jsx_node.type == "jsx_element":
            return jsx_node.child_by_field_name("open_tag")
        return None

    def get_tag_name(self, opening_node, content_bytes: bytes) -> str:
        if not opening_node:
            return ""
        for idx, child in enumerate(opening_node.children):
            if opening_node.field_name_for_child(idx) == "name":
                return self._node_text(child, content_bytes).strip()
        return ""

    def get_attributes(self, opening_node, content_bytes: bytes) -> list[JsxAttributeInfo]:
        attrs: list[JsxAttributeInfo] = []
        if not opening_node:
            return attrs

        for idx, child in enumerate(opening_node.children):
            if opening_node.field_name_for_child(idx) != "attribute":
                continue
            if child.type != "jsx_attribute":
                continue

            name_node = None
            value_node = None
            for j, attr_child in enumerate(child.children):
                if attr_child.type in {"property_identifier", "identifier", "jsx_identifier"} and name_node is None:
                    name_node = attr_child
                    continue
                if child.field_name_for_child(j) == "value" and value_node is None:
                    value_node = attr_child
                    continue
                if value_node is None and attr_child.type in {"string", "jsx_expression", "template_string"}:
                    value_node = attr_child

            name = self._node_text(name_node, content_bytes).strip()
            if not name:
                continue

            raw_value = ""
            static_value: str | None = ""
            if value_node is not None:
                raw_value = self._node_text(value_node, content_bytes).strip()
                static_value = self._extract_static_value(value_node.type, raw_value)

            attrs.append(
                JsxAttributeInfo(
                    name=name,
                    raw_value=raw_value,
                    static_value=static_value,
                    line=child.start_point.row + 1,
                )
            )
        return attrs

    def direct_child_elements(self, jsx_element_node) -> list:
        children: list = []
        if not jsx_element_node or jsx_element_node.type != "jsx_element":
            return children
        for child in getattr(jsx_element_node, "children", []) or []:
            if child.type in {"jsx_element", "jsx_self_closing_element"}:
                children.append(child)
        return children

    def _language_for(self, file_path: str) -> str:
        low = str(file_path or "").lower()
        if low.endswith(".tsx"):
            return "tsx"
        if low.endswith(".ts"):
            return "typescript"
        return "javascript"

    def _node_text(self, node, content_bytes: bytes) -> str:
        if not node:
            return ""
        return content_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def _extract_static_value(self, value_type: str, raw_value: str) -> str | None:
        text = (raw_value or "").strip()
        if text == "":
            return ""
        if value_type == "string":
            return self._strip_quotes(text)
        if value_type == "template_string":
            if "${" in text:
                return None
            return self._strip_quotes(text)
        if value_type == "jsx_expression":
            if not (text.startswith("{") and text.endswith("}")):
                return None
            inner = text[1:-1].strip()
            if not inner:
                return ""
            if (inner.startswith("'") and inner.endswith("'")) or (inner.startswith('"') and inner.endswith('"')):
                return self._strip_quotes(inner)
            if inner.startswith("`") and inner.endswith("`") and "${" not in inner:
                return self._strip_quotes(inner)
            return None
        return None

    def _strip_quotes(self, value: str) -> str:
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"', "`"}:
            return value[1:-1]
        return value

