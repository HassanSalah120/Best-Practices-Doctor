"""Advanced React prop/key safety rules."""

from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class _AdvancedFrontendRegexRule(Rule):
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        return []

    def _line_for_offset(self, content: str, offset: int) -> int:
        return (content or "").count("\n", 0, max(0, offset)) + 1

    def _skip_file(self, file_path: str) -> bool:
        normalized = (file_path or "").replace("\\", "/").lower()
        if not normalized.endswith((".js", ".jsx", ".ts", ".tsx")):
            return True
        parts = {part for part in normalized.split("/") if part}
        return bool(parts.intersection({"test", "tests", "__tests__", "fixtures", "stories", "storybook"}))


class InlinePropObjectArrayRule(_AdvancedFrontendRegexRule):
    id = "inline-prop-object-array"
    name = "Inline Object/Array Prop Creation"
    description = "Inline objects or arrays passed as props create new references on every render."
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    severity_weight = 5
    confidence = "high"
    fix_suggestion = "Move the object/array outside the render or wrap it in useMemo to preserve referential stability."
    examples = {
        "bad": "<Chart config={{ compact: true }} items={[1, 2, 3]} />",
        "good": "const items = useMemo(() => [1, 2, 3], []); <Chart items={items} />",
    }
    priority = 3
    group = "React Performance"
    applies_to = ["react-component"]
    references = []
    related_rules = ["context-provider-inline-value", "missing-usememo-for-expensive-calc"]
    false_positive_notes = "Inline style/className on native HTML elements is intentionally ignored."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "react", "type": "performance", "concern": "props"}

    _CUSTOM_ELEMENT = re.compile(r"<(?P<tag>[A-Z][A-Za-z0-9_.]*)\b(?P<attrs>[^<>]*)/?>", re.DOTALL)
    _INLINE_PROP = re.compile(
        r"(?P<prop>[A-Za-z_$][A-Za-z0-9_$-]*)\s*=\s*\{\s*(?P<value>\[[\s\S]*?\]|\{[\s\S]*?\})\s*\}",
        re.DOTALL,
    )
    _ALLOWED_INLINE_PROPS = {"className", "style"}

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._skip_file(file_path):
            return []

        text = content or ""
        findings: list[Finding] = []
        for element in self._CUSTOM_ELEMENT.finditer(text):
            attrs = element.group("attrs") or ""
            for attr in self._INLINE_PROP.finditer(attrs):
                prop = attr.group("prop")
                if prop in self._ALLOWED_INLINE_PROPS:
                    continue
                value = (attr.group("value") or "").lstrip()
                kind = "array" if value.startswith("[") else "object"
                line = self._line_for_offset(text, element.start() + attr.start())
                findings.append(
                    self.create_finding(
                        title="Inline object or array prop creates unstable reference",
                        file=file_path,
                        line_start=line,
                        context=f"{file_path}:{line}:{prop}",
                        description=self.description,
                        why_it_matters="New prop references can defeat memoization and trigger avoidable child re-renders.",
                        suggested_fix=self.fix_suggestion,
                        confidence=0.9,
                        tags=["react", "performance", "props"],
                        evidence_signals=[f"prop={prop}", f"inline_value={kind}"],
                    ),
                )
        return findings[: max(1, int(self.get_threshold("max_findings_per_file", 3)))]


class UnstableReactKeyRule(_AdvancedFrontendRegexRule):
    id = "unstable-react-key"
    name = "Unstable React Key"
    description = "React keys must be stable and unique. Unstable keys can cause incorrect UI updates and bugs."
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.HIGH
    severity_weight = 8
    confidence = "high"
    fix_suggestion = "Use a stable unique identifier such as database id instead of derived or dynamic values."
    examples = {
        "bad": "{items.map(item => <Row key={t(item.name)} />)}",
        "good": "{items.map(item => <Row key={item.id} />)}",
    }
    priority = 2
    group = "React Stability"
    applies_to = ["react-component"]
    references = []
    related_rules = ["react-no-random-key", "duplicate-key-source", "missing-key-on-list-render"]
    false_positive_notes = "Composite keys can be valid when every segment is stable; this rule targets dynamic calls and weak standalone identifiers."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "react", "type": "quality", "concern": "keys"}

    _KEY_EXPR = re.compile(r"\bkey\s*=\s*\{\s*(?P<expr>`[^`]*`|[^}]+)\s*\}", re.DOTALL)
    _STATIC_ARRAY_DECL = re.compile(
        r"(?:const|let)\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:as\s+const\s*)?\[(?P<body>[^\]]*)\]",
        re.DOTALL,
    )
    _DEDUPED_ARRAY_DECL = re.compile(
        r"(?:const|let)\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*Array\.from\s*\(\s*new\s+Set\s*\(",
        re.DOTALL,
    )
    _MAP_CALLBACK = re.compile(
        r"(?P<source>[A-Za-z_$][A-Za-z0-9_$.]*)\.map\s*\(\s*(?:\(\s*)?(?P<item>[A-Za-z_$][A-Za-z0-9_$]*)",
        re.DOTALL,
    )
    _STABLE_MEMBER = re.compile(
        r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\?\.)?\.(?:id|uuid|key|public_id|slug|code|value|name)\s*$",
        re.IGNORECASE,
    )
    _STABLE_IDENTIFIER = re.compile(
        r"^(?:id|uuid|key|public_id|slug|code|value|status|type|role|lang|locale|category|feature|group|tz|time|channel)$",
        re.IGNORECASE,
    )
    _CALL = re.compile(r"\b[A-Za-z_$][A-Za-z0-9_$.]*\s*\(")
    _STRING_BINARY = re.compile(r"(?:['\"][^'\"]*['\"]\s*\+|\+\s*['\"][^'\"]*['\"])")

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._skip_file(file_path):
            return []

        text = content or ""
        static_sources = self._static_collection_names(text)
        stable_value_sources = static_sources | self._deduped_collection_names(text)
        map_sources = self._map_sources(text)
        findings: list[Finding] = []
        for match in self._KEY_EXPR.finditer(text):
            expr = " ".join((match.group("expr") or "").strip().split())
            if not expr or self._is_stable_key_expression(expr, text, match.start(), stable_value_sources, map_sources):
                continue
            reason = self._unstable_reason(expr)
            if not reason:
                continue
            line = self._line_for_offset(text, match.start())
            findings.append(
                self.create_finding(
                    title="React key uses unstable value",
                    file=file_path,
                    line_start=line,
                    context=f"{file_path}:{line}:{expr}",
                    description=self.description,
                    why_it_matters="Unstable keys break React reconciliation and can preserve or discard the wrong component state.",
                    suggested_fix=self.fix_suggestion,
                    confidence=0.9,
                    tags=["react", "rendering", "keys"],
                    evidence_signals=[f"key_expression={expr}", f"reason={reason}"],
                ),
            )
        return findings[: max(1, int(self.get_threshold("max_findings_per_file", 3)))]

    def _is_stable_key_expression(
        self,
        expr: str,
        text: str,
        offset: int,
        static_sources: set[str],
        map_sources: dict[str, set[str]],
    ) -> bool:
        normalized = expr.strip()
        if self._STABLE_IDENTIFIER.match(normalized) or self._STABLE_MEMBER.match(normalized):
            return True
        if self._is_explicit_row_key_helper(normalized, text, offset, map_sources):
            return True
        if not self._is_list_key_context(text, offset):
            return True
        if self._is_stable_composite(normalized, text, offset, static_sources, map_sources):
            return True
        if self._is_from_static_collection(normalized, text, offset, static_sources, map_sources):
            return True
        return bool(self._is_hook_generated_key(normalized, text, offset))

    def _unstable_reason(self, expr: str) -> str:
        if "Math.random(" in expr or "Date.now(" in expr:
            return "runtime_generated"
        if self._CALL.search(expr):
            return "call_expression"
        if expr.startswith("`") and "${" in expr:
            return "template_literal"
        if self._STRING_BINARY.search(expr):
            return "string_binary_expression"
        if re.match(r"^[A-Za-z_$][A-Za-z0-9_$]*$", expr) and not self._STABLE_IDENTIFIER.match(expr):
            return "weak_identifier"
        return ""

    def _static_collection_names(self, text: str) -> set[str]:
        names: set[str] = set()
        for match in self._STATIC_ARRAY_DECL.finditer(text or ""):
            name = str(match.group("name") or "")
            body = str(match.group("body") or "")
            if not name or not body:
                continue
            if self._array_body_is_static(body):
                names.add(name)
        return names

    def _array_body_is_static(self, body: str) -> bool:
        stripped = " ".join((body or "").split())
        if not stripped:
            return False
        if re.fullmatch(r"(?:['\"][^'\"]+['\"]|\d+)(?:\s*,\s*(?:['\"][^'\"]+['\"]|\d+))*\s*,?", stripped):
            return True
        return bool(re.search(r"\{\s*(?:id|value|key|code|slug|name|type|status)\s*:\s*['\"][^'\"]+['\"]", stripped))

    def _deduped_collection_names(self, text: str) -> set[str]:
        return {
            str(match.group("name") or "")
            for match in self._DEDUPED_ARRAY_DECL.finditer(text or "")
            if str(match.group("name") or "")
        }

    def _map_sources(self, text: str) -> dict[str, set[str]]:
        sources: dict[str, set[str]] = {}
        for match in self._MAP_CALLBACK.finditer(text or ""):
            item = str(match.group("item") or "")
            source = str(match.group("source") or "").split(".")[-1]
            if item and source:
                sources.setdefault(item, set()).add(source)
        return sources

    def _is_from_static_collection(
        self,
        expr: str,
        text: str,
        offset: int,
        static_sources: set[str],
        map_sources: dict[str, set[str]],
    ) -> bool:
        token = expr.split(".")[0].strip()
        if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", token):
            return False
        sources = map_sources.get(token, set())
        if sources.intersection(static_sources):
            return True
        prior = (text or "")[:offset]
        inline_static_map = re.compile(
            rf"\(?\s*\[\s*(?:['\"][^'\"]+['\"]|\d+)(?:\s*,\s*(?:['\"][^'\"]+['\"]|\d+))*\s*\]\s*(?:as\s+const\s*)?\)?\s*"
            rf"\.map\s*\(\s*(?:\(\s*)?{re.escape(token)}\b",
            re.DOTALL,
        )
        if inline_static_map.search(prior):
            return True
        for source in static_sources:
            inline_spread_map = re.compile(
                rf"\[\s*[\s\S]*\.\.\.\s*{re.escape(source)}\b[\s\S]*\]\s*"
                rf"\.map\s*\(\s*(?:\(\s*)?{re.escape(token)}\b",
                re.DOTALL,
            )
            if inline_spread_map.search(prior):
                return True
        return False

    def _is_stable_composite(
        self,
        expr: str,
        text: str,
        offset: int,
        stable_sources: set[str],
        map_sources: dict[str, set[str]],
    ) -> bool:
        if not (expr.startswith("`") and "${" in expr):
            return False
        if "Math.random(" in expr or "Date.now(" in expr:
            return False
        if re.search(r"\b(t|i18n\.t|translate)\s*\(", expr):
            return False
        dynamic_calls = [
            call
            for call in self._CALL.findall(expr)
            if not re.search(r"(?:^String\s*\($|\.(toString|trim|toLowerCase|toUpperCase)\s*\($)", call)
        ]
        if dynamic_calls:
            return False
        fields = set(re.findall(r"\$\{\s*([^}]+?)\s*\}", expr))
        if not fields:
            return False
        if any(self._is_from_static_collection(field.strip(), text, offset, stable_sources, map_sources) for field in fields):
            return True
        if len(fields) == 1:
            only_field = next(iter(fields)).strip()
            if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", only_field) and not self._STABLE_IDENTIFIER.match(only_field):
                return False
        stable_field = re.compile(
            r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$"
            r"|^[A-Za-z_$][A-Za-z0-9_$]*\s*\|\|\s*['\"][^'\"]+['\"]$"
            r"|^String\s*\(\s*[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*\s*\)$",
        )
        return all(stable_field.match(field.strip()) for field in fields)

    def _is_list_key_context(self, text: str, offset: int) -> bool:
        prior = (text or "")[:offset]
        window = prior[-500:]
        last_map = window.rfind(".map(")
        if last_map < 0:
            return False
        last_statement_break = max(window.rfind(";"), window.rfind("\n\n"))
        return last_map > last_statement_break

    def _is_explicit_row_key_helper(
        self,
        expr: str,
        text: str,
        offset: int,
        map_sources: dict[str, set[str]],
    ) -> bool:
        match = re.fullmatch(
            r"(?P<fn>[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*\(\s*(?P<arg>[A-Za-z_$][A-Za-z0-9_$]*)\s*\)",
            expr,
        )
        if not match:
            return False
        fn_name = match.group("fn").split(".")[-1].lower()
        arg = match.group("arg")
        if "key" not in fn_name or arg not in map_sources:
            return False
        prior = (text or "")[:offset]
        helper_name = re.escape(match.group("fn").split(".")[-1])
        return bool(
            re.search(rf"\b(?:const|function)\s+{helper_name}\b", prior)
            or re.search(rf"\b{helper_name}\s*=", prior)
            or re.search(r"\browKey\b", prior),
        )

    def _is_hook_generated_key(self, expr: str, text: str, offset: int) -> bool:
        if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", expr):
            return False
        prior = (text or "")[:offset]
        if re.search(rf"\bconst\s+{re.escape(expr)}\s*=", prior):
            return True
        return bool(re.search(rf"\b{re.escape(expr)}s?\s*=\s*use[A-Z][A-Za-z0-9_]*\s*\(", prior))


class LooseDefaultObjectPropRule(_AdvancedFrontendRegexRule):
    id = "loose-default-object-prop"
    name = "Loose Default Object Prop"
    description = "Defaulting props to an empty object can hide missing data and lead to runtime bugs."
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    severity_weight = 5
    confidence = "high"
    fix_suggestion = "Use strict typing and explicit defaults instead of {}."
    examples = {
        "bad": "function Panel({ data = {} }) { return <div />; }",
        "good": "type Props = { data: PanelData }; function Panel({ data }: Props) { return <div />; }",
    }
    priority = 3
    group = "React Stability"
    applies_to = ["react-component"]
    references = []
    related_rules = ["missing-props-type", "controlled-uncontrolled-input-mismatch"]
    false_positive_notes = "Only uppercase React component signatures are scanned to avoid ordinary utility function defaults."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "react", "type": "quality", "concern": "props"}

    _COMPONENT_PARAMS = re.compile(
        r"(?:export\s+)?function\s+[A-Z][A-Za-z0-9_]*\s*\(\s*\{(?P<fn_params>[^)]*)\}\s*\)"
        r"|(?:export\s+)?(?:const|let)\s+[A-Z][A-Za-z0-9_]*\s*=\s*\(\s*\{(?P<arrow_params>[^)]*)\}\s*\)\s*=>",
        re.DOTALL,
    )
    _EMPTY_OBJECT_DEFAULT = re.compile(r"\b(?P<prop>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*\{\s*\}")

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._skip_file(file_path):
            return []

        text = content or ""
        if "<" not in text:
            return []

        findings: list[Finding] = []
        for component in self._COMPONENT_PARAMS.finditer(text):
            params = component.group("fn_params") or component.group("arrow_params") or ""
            for match in self._EMPTY_OBJECT_DEFAULT.finditer(params):
                prop = match.group("prop")
                line = self._line_for_offset(text, component.start() + match.start())
                findings.append(
                    self.create_finding(
                        title="Prop defaults to loose empty object",
                        file=file_path,
                        line_start=line,
                        context=f"{file_path}:{line}:{prop}",
                        description=self.description,
                        why_it_matters="An empty object default masks missing required data and weakens TypeScript's signal.",
                        suggested_fix=self.fix_suggestion,
                        confidence=0.9,
                        tags=["typescript", "safety", "props"],
                        evidence_signals=[f"prop={prop}", "default_object={}"],
                    ),
                )
        return findings[: max(1, int(self.get_threshold("max_findings_per_file", 3)))]
