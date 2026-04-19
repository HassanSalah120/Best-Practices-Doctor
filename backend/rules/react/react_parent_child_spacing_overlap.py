"""
React Parent/Child Spacing Overlap Rule

Detects direct parent-child JSX nodes that apply overlapping spacing utilities
with the same responsive scope. The first version is intentionally conservative:
- direct parent-child only
- spacing families only (padding/margin/gap/space-x/space-y)
- static className values only (skip dynamic interpolations)
"""

from __future__ import annotations

import re
from typing import Iterable

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule

try:
    import tree_sitter_javascript as tsjs
    import tree_sitter_typescript as tsts
    from tree_sitter import Language, Parser

    _TREE_SITTER_READY = True
except Exception:
    Language = None
    Parser = None
    _TREE_SITTER_READY = False


class ReactParentChildSpacingOverlapRule(Rule):
    id = "react-parent-child-spacing-overlap"
    name = "Parent/Child Spacing Overlap"
    description = "Detects overlapping spacing utilities between direct JSX parent-child nodes"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    type = "ast"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]
    applicable_project_types: list[str] = []

    _ALLOWLIST_PATH_MARKERS = (".test.", ".spec.", "__tests__", ".stories.", "/node_modules/", "/dist/")
    _RESPONSIVE_SCOPES = {"base", "sm", "md", "lg", "xl", "2xl"}
    _STABLE_VALUE_PATTERN = re.compile(r"^[A-Za-z0-9._/%\-[\]]+$")
    _SPACING_KEYS = {
        "p",
        "px",
        "py",
        "pt",
        "pb",
        "pl",
        "pr",
        "m",
        "mx",
        "my",
        "mt",
        "mb",
        "ml",
        "mr",
        "gap",
        "gap-x",
        "gap-y",
        "space-x",
        "space-y",
    }
    _CONTEXTUAL_VARIANT_PREFIXES = {
        # Intentionally skip contextual/state variants for v1 to reduce noise.
        "hover",
        "focus",
        "active",
        "dark",
        "group-hover",
        "peer",
        "rtl",
        "ltr",
    }

    def __init__(self, config):
        super().__init__(config)
        self._parsers: dict[str, Parser] = {}
        if _TREE_SITTER_READY:
            try:
                self._parsers["javascript"] = Parser(Language(tsjs.language()))
                self._parsers["typescript"] = Parser(Language(tsts.language_typescript()))
                self._parsers["tsx"] = Parser(Language(tsts.language_tsx()))
            except Exception:
                self._parsers = {}

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
        text = content or ""
        if "className" not in text and "class=" not in text:
            return []

        normalized_path = str(file_path or "").lower().replace("\\", "/")
        if any(marker in normalized_path for marker in self._ALLOWLIST_PATH_MARKERS):
            return []

        tree = self._parse_tree(file_path, text)
        if not tree or not getattr(tree, "root_node", None):
            return []

        max_findings_per_file = max(1, int(self.get_threshold("max_findings_per_file", 2)))
        require_same_value = bool(self.get_threshold("require_same_value", True))
        allowed_scopes = self._normalized_allowed_scopes(
            self.get_threshold("allowed_responsive_scopes", ["base", "sm", "md", "lg", "xl", "2xl"])
        )
        if not allowed_scopes:
            allowed_scopes = {"base"}

        content_bytes = text.encode("utf-8")
        findings: list[Finding] = []
        seen_pairs: set[tuple[int, int, str, str, str]] = set()

        for node in self._walk(tree.root_node):
            if len(findings) >= max_findings_per_file:
                break
            if node.type != "jsx_element":
                continue

            parent_open = node.child_by_field_name("open_tag")
            parent_spacing = self._extract_spacing_map(parent_open, content_bytes, allowed_scopes)
            if not parent_spacing:
                continue

            parent_line = node.start_point.row + 1
            for child in self._direct_child_elements(node):
                if len(findings) >= max_findings_per_file:
                    break
                child_open = child if child.type == "jsx_self_closing_element" else child.child_by_field_name("open_tag")
                child_spacing = self._extract_spacing_map(child_open, content_bytes, allowed_scopes)
                if not child_spacing:
                    continue

                child_line = child.start_point.row + 1
                overlaps = self._find_overlaps(parent_spacing, child_spacing, require_same_value)
                for scope, spacing_key, parent_value, child_value in overlaps:
                    pair_key = (parent_line, child_line, scope, spacing_key, parent_value if require_same_value else "")
                    if pair_key in seen_pairs:
                        continue
                    seen_pairs.add(pair_key)

                    confidence = 0.92 if parent_value == child_value else 0.87
                    findings.append(
                        self.create_finding(
                            title="Direct parent/child spacing overlap detected",
                            context=f"parent:{parent_line}->child:{child_line}:{scope}:{spacing_key}",
                            file=file_path,
                            line_start=child_line,
                            description=(
                                "Detected overlapping spacing utilities between direct parent and child JSX nodes "
                                f"for `{spacing_key}` at `{scope}` scope."
                            ),
                            why_it_matters=(
                                "Duplicating spacing ownership across container and immediate child increases layout drift risk "
                                "and makes spacing behavior harder to reason about during UI changes."
                            ),
                            suggested_fix=(
                                "Assign spacing ownership to one level (parent or child) for this axis/scope, and keep the other node "
                                "focused on its own local layout concerns."
                            ),
                            confidence=confidence,
                            tags=["react", "layout", "spacing", "duplication", "tailwind"],
                            evidence_signals=[
                                f"overlap_family={spacing_key}",
                                f"parent_line={parent_line}",
                                f"child_line={child_line}",
                                f"responsive_scope={scope}",
                                f"parent_value={parent_value}",
                                f"child_value={child_value}",
                                f"require_same_value={int(require_same_value)}",
                                "parser=tree-sitter",
                            ],
                            metadata={
                                "decision_profile": {
                                    "overlap_family": spacing_key,
                                    "responsive_scope": scope,
                                    "parent_line": parent_line,
                                    "child_line": child_line,
                                    "parent_value": parent_value,
                                    "child_value": child_value,
                                    "require_same_value": require_same_value,
                                    "parser": "tree-sitter",
                                }
                            },
                        )
                    )
                    if len(findings) >= max_findings_per_file:
                        break

        return findings

    def _parse_tree(self, file_path: str, content: str):
        parser = self._parsers.get(self._language_for(file_path))
        if not parser:
            return None
        try:
            return parser.parse(content.encode("utf-8"))
        except Exception:
            return None

    def _language_for(self, file_path: str) -> str:
        low = str(file_path or "").lower()
        if low.endswith(".tsx"):
            return "tsx"
        if low.endswith(".ts"):
            return "typescript"
        return "javascript"

    def _walk(self, node) -> Iterable:
        yield node
        for child in getattr(node, "children", []) or []:
            yield from self._walk(child)

    def _node_text(self, node, content_bytes: bytes) -> str:
        if not node:
            return ""
        return content_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def _direct_child_elements(self, jsx_element_node) -> list:
        children: list = []
        for child in getattr(jsx_element_node, "children", []) or []:
            if child.type in {"jsx_element", "jsx_self_closing_element"}:
                children.append(child)
        return children

    def _extract_spacing_map(
        self,
        opening_node,
        content_bytes: bytes,
        allowed_scopes: set[str],
    ) -> dict[tuple[str, str], str]:
        tokens = self._extract_static_class_tokens(opening_node, content_bytes)
        if not tokens:
            return {}

        out: dict[tuple[str, str], str] = {}
        for token in tokens:
            parsed = self._parse_spacing_token(token)
            if not parsed:
                continue
            scope, spacing_key, value = parsed
            if scope not in allowed_scopes:
                continue
            out[(scope, spacing_key)] = value
        return out

    def _extract_static_class_tokens(self, opening_node, content_bytes: bytes) -> list[str]:
        if not opening_node:
            return []

        tokens: list[str] = []
        for idx, child in enumerate(opening_node.children):
            if opening_node.field_name_for_child(idx) != "attribute":
                continue
            attr_name, attr_value = self._extract_attr_name_and_value(child, content_bytes)
            if attr_name not in {"className", "class"}:
                continue
            static_value = self._extract_static_value(attr_value, content_bytes)
            if static_value is None:
                # Skip this element entirely when className is dynamic.
                return []
            tokens.extend(tok for tok in static_value.split() if tok)
        return tokens

    def _extract_attr_name_and_value(self, attr_node, content_bytes: bytes) -> tuple[str, object | None]:
        name_node = None
        value_node = None
        for idx, child in enumerate(attr_node.children):
            field = attr_node.field_name_for_child(idx)
            if field == "name":
                name_node = child
            elif field == "value":
                value_node = child

        if name_node is None:
            for child in attr_node.children:
                if child.type in {"property_identifier", "identifier", "jsx_identifier"}:
                    name_node = child
                    break
        if value_node is None:
            for child in attr_node.children:
                if child.type in {"string", "jsx_expression", "template_string"}:
                    value_node = child
                    break

        name = self._node_text(name_node, content_bytes).strip() if name_node else ""
        return name, value_node

    def _extract_static_value(self, value_node, content_bytes: bytes) -> str | None:
        if value_node is None:
            return ""
        text = self._node_text(value_node, content_bytes).strip()
        if not text:
            return ""

        if value_node.type == "string":
            return self._strip_quotes(text)
        if value_node.type == "template_string":
            if "${" in text:
                return None
            return self._strip_quotes(text)
        if value_node.type == "jsx_expression":
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

    def _strip_quotes(self, text: str) -> str:
        if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"', "`"}:
            return text[1:-1]
        return text

    def _normalized_allowed_scopes(self, raw) -> set[str]:
        if isinstance(raw, str):
            values = [raw]
        elif isinstance(raw, (list, tuple, set)):
            values = list(raw)
        else:
            values = []
        out = set()
        for value in values:
            s = str(value or "").strip().lower()
            if s in self._RESPONSIVE_SCOPES:
                out.add(s)
        return out

    def _parse_spacing_token(self, token: str) -> tuple[str, str, str] | None:
        raw = str(token or "").strip()
        if not raw:
            return None

        parts = raw.split(":")
        scope = "base"
        utility = raw
        if len(parts) == 2:
            prefix, utility = parts[0].strip(), parts[1].strip()
            if prefix in self._CONTEXTUAL_VARIANT_PREFIXES:
                return None
            if prefix not in self._RESPONSIVE_SCOPES:
                return None
            scope = prefix
        elif len(parts) > 2:
            return None

        utility = utility.lstrip("!")
        negative = False
        if utility.startswith("-"):
            negative = True
            utility = utility[1:]
        if not utility:
            return None

        spacing_key, value = self._split_spacing_utility(utility)
        if not spacing_key or spacing_key not in self._SPACING_KEYS:
            return None
        if negative:
            value = f"-{value}"
        if not self._is_stable_value(value):
            return None
        return scope, spacing_key, value

    def _split_spacing_utility(self, utility: str) -> tuple[str, str]:
        for prefix in (
            "space-x-",
            "space-y-",
            "gap-x-",
            "gap-y-",
            "gap-",
            "px-",
            "py-",
            "pt-",
            "pb-",
            "pl-",
            "pr-",
            "p-",
            "mx-",
            "my-",
            "mt-",
            "mb-",
            "ml-",
            "mr-",
            "m-",
        ):
            if utility.startswith(prefix):
                key = prefix[:-1]
                value = utility[len(prefix) :].strip()
                return key, value

        # Support compact patterns where single-letter key can appear first in matching order.
        if utility.startswith("p") and "-" in utility:
            key, value = utility.split("-", 1)
            if key in {"p", "px", "py", "pt", "pb", "pl", "pr"}:
                return key, value.strip()
        if utility.startswith("m") and "-" in utility:
            key, value = utility.split("-", 1)
            if key in {"m", "mx", "my", "mt", "mb", "ml", "mr"}:
                return key, value.strip()

        return "", ""

    def _is_stable_value(self, value: str) -> bool:
        v = str(value or "").strip()
        if not v:
            return False
        low = v.lower()
        if "var(" in low or "calc(" in low or "theme(" in low:
            return False
        if any(ch in v for ch in ("{", "}", "$", "(", ")")):
            return False
        return bool(self._STABLE_VALUE_PATTERN.match(v))

    def _find_overlaps(
        self,
        parent_spacing: dict[tuple[str, str], str],
        child_spacing: dict[tuple[str, str], str],
        require_same_value: bool,
    ) -> list[tuple[str, str, str, str]]:
        overlaps: list[tuple[str, str, str, str]] = []
        for key, parent_value in parent_spacing.items():
            if key not in child_spacing:
                continue
            child_value = child_spacing[key]
            if require_same_value and parent_value != child_value:
                continue
            scope, spacing_key = key
            overlaps.append((scope, spacing_key, parent_value, child_value))
        return overlaps
