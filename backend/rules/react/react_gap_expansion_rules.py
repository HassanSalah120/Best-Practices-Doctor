"""
React gap expansion rules (AST-first, conservative).

These rules focus on high-value React correctness/performance gaps with
strong-signal detection and low-noise defaults.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from rules.base import Rule
from rules.react.jsx_tree_sitter import JsxAttributeInfo, JsxTreeSitterHelper
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics

_TEST_PATH_MARKERS = ("tests", "test", "__tests__", "stories", "storybook", "fixtures")
_PAGE_PATH_MARKERS = ("pages", "screens", "views")
_NON_RENDER_PATH_MARKERS = ("hooks", "utils", "helpers", "lib", "services", "types")
_CHILD_COMPONENT_PATH_MARKERS = ("components", "fragments", "partials", "utils", "hooks", "services")

# Suffixes that suggest a file is a sub-component/section, not a full page
_CHILD_COMPONENT_NAME_HINTS = (
    "content",
    "section",
    "list",
    "grid",
    "card",
    "cards",
    "item",
    "items",
    "widget",
    "panel",
    "header",
    "footer",
    "banner",
    "hero",
    "modal",
    "dialog",
    "table",
    "row",
    "column",
    "noise",
    "background",
    "benefits",
    "navbar",
    "form",
    "drawer",
    "view",
    "sidebar",
    "wizard",
    "step",
    "steps",
    "proof",
    "preview",
    "skeleton",
    "overlay",
    "wrapper",
)


@dataclass(frozen=True)
class _EffectBlock:
    body: str
    deps: str
    line: int


class _ReactGapAstRuleBase(Rule):
    type = "ast"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    def __init__(self, config):
        super().__init__(config)
        self._jsx = JsxTreeSitterHelper()

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        return []

    def _get_path_segments(self, file_path: str) -> list[str]:
        return [s for s in (file_path or "").replace("\\", "/").lower().split("/") if s]

    def _skip_file(self, file_path: str) -> bool:
        segments = self._get_path_segments(file_path)
        return any(marker in segments for marker in _TEST_PATH_MARKERS)

    def _is_page_like(self, file_path: str) -> bool:
        low = (file_path or "").lower()
        if not low.endswith((".tsx", ".jsx", ".blade.php")):
            return False
        if low.endswith((".d.ts", ".types.ts", ".types.tsx")):
            return False
        segments = self._get_path_segments(file_path)
        return any(marker in segments for marker in _PAGE_PATH_MARKERS)

    def _is_non_render_module(self, file_path: str) -> bool:
        segments = self._get_path_segments(file_path)
        return any(marker in segments for marker in _NON_RENDER_PATH_MARKERS)

    def _looks_like_child_composition(self, file_path: str, content: str) -> bool:
        text = content or ""
        # If it has explicit indexability or heading signals, it's likely a page.
        if re.search(r"<(?:Head|Helmet|h1)\b", text, re.IGNORECASE):
            return False

        segments = self._get_path_segments(file_path)
        if any(marker in segments for marker in _CHILD_COMPONENT_PATH_MARKERS):
            return True

        full_name = (file_path or "").replace("\\", "/").split("/")[-1].lower()
        if ".components." in full_name or ".utils." in full_name:
            return True

        from pathlib import Path
        stem = Path(file_path or "").stem
        for hint in _CHILD_COMPONENT_NAME_HINTS:
            low_stem = stem.lower()
            if low_stem == hint or low_stem.endswith(f"_{hint}") or low_stem.endswith(f"-{hint}"):
                return True

            if low_stem.endswith(hint):
                prefix_idx = len(stem) - len(hint)
                if prefix_idx <= 0:
                    return True
                if stem[prefix_idx].isupper() or stem[prefix_idx - 1] in "_-":
                    return True
        return False

    def _looks_like_render_module(self, content: str) -> bool:
        text = content or ""
        return bool(re.search(r"<[A-Za-z][A-Za-z0-9_.:-]*(?:\s|/?>)", text))

    def _content_bytes(self, content: str) -> bytes:
        return (content or "").encode("utf-8")

    def _attr_map(self, attrs: list[JsxAttributeInfo]) -> dict[str, JsxAttributeInfo]:
        return {a.name: a for a in attrs}

    def _attr_value(self, attrs: dict[str, JsxAttributeInfo], key: str) -> str:
        item = attrs.get(key)
        if not item:
            return ""
        return str(item.static_value or "").strip()

    def _node_text(self, node, content_bytes: bytes) -> str:
        if not node:
            return ""
        return content_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def _line_for_offset(self, content: str, offset: int) -> int:
        return (content or "").count("\n", 0, max(0, offset)) + 1

    def _iter_effect_blocks(self, content: str) -> Iterable[_EffectBlock]:
        pattern = re.compile(
            r"useEffect\s*\(\s*(?:\(\)\s*=>\s*\{(?P<body1>.*?)\}|function\s*\([^)]*\)\s*\{(?P<body2>.*?)\})\s*,\s*\[(?P<deps>[^\]]*)\]\s*\)",
            re.IGNORECASE | re.DOTALL,
        )
        for match in pattern.finditer(content or ""):
            body = (match.group("body1") or match.group("body2") or "").strip()
            deps = (match.group("deps") or "").strip()
            if not body:
                continue
            yield _EffectBlock(body=body, deps=deps, line=self._line_for_offset(content, match.start()))

    def _public_surface_enabled(self, facts: Facts) -> bool:
        ctx = getattr(facts, "project_context", None)
        if ctx is None:
            return False
        project_type = str(
            getattr(ctx, "project_type", "")
            or getattr(ctx, "project_business_context", "")
            or "",
        ).strip().lower()
        if project_type in {"public_website_with_dashboard", "portal_based_business_app", "saas_platform"}:
            return True
        capabilities = (
            getattr(ctx, "capabilities", None)
            or getattr(ctx, "backend_capabilities", None)
            or {}
        )
        for key in ("mixed_public_dashboard", "public_marketing_site", "multi_role_portal"):
            payload = capabilities.get(key)
            if isinstance(payload, dict) and bool(payload.get("enabled", False)):
                return True
        return False


class AvoidPropsToStateCopyRule(_ReactGapAstRuleBase):
    id = "avoid-props-to-state-copy"
    name = "Avoid Props-to-State Copy"
    description = "Detects direct props mirroring into useState initializers"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY

    _DIRECT_PROPS_INIT = re.compile(
        r"const\s*\[\s*(?P<state>[A-Za-z_]\w*)\s*,\s*(?P<setter>set[A-Za-z_]\w*)\s*\]\s*=\s*useState\s*\(\s*props\.(?P<prop>[A-Za-z_]\w*)\s*\)",
        re.IGNORECASE,
    )

    _DESTRUCTURED_FN = re.compile(
        r"(?:function\s+[A-Z]\w*\s*\(\s*\{(?P<props1>[^}]*)\}\s*\)|const\s+[A-Z]\w*\s*=\s*\(\s*\{(?P<props2>[^}]*)\}\s*\)\s*=>)",
        re.IGNORECASE,
    )
    _STATE_INIT_TOKEN = re.compile(
        r"const\s*\[\s*(?P<state>[A-Za-z_]\w*)\s*,\s*(?P<setter>set[A-Za-z_]\w*)\s*\]\s*=\s*useState\s*\(\s*(?P<token>[A-Za-z_]\w*)\s*\)",
        re.IGNORECASE,
    )
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Refactor the component code to remove the avoid props-to-state copy pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 3
    group = 'React Stability'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'ast'
    analysis_cost = 'medium'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'avoid-props-to'}

    def analyze_ast(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._skip_file(file_path):
            return []

        findings: list[Finding] = []
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 2)))
        text = content or ""

        for match in self._DIRECT_PROPS_INIT.finditer(text):
            line = self._line_for_offset(text, match.start())
            findings.append(
                self.create_finding(
                    title="Props copied into local state",
                    context=f"{file_path}:{line}:{match.group('state')}",
                    file=file_path,
                    line_start=line,
                    description=(
                        "Local state is initialized directly from `props` and will drift unless manually synchronized."
                    ),
                    why_it_matters=(
                        "Mirroring props into state is a common source of stale UI and synchronization bugs."
                    ),
                    suggested_fix=(
                        "Derive the value from props during render, or document an explicit local divergence workflow."
                    ),
                    confidence=0.9,
                    tags=["react", "state", "props", "derived-state"],
                    evidence_signals=[
                        "props_copy_signal=direct",
                        f"state={match.group('state')}",
                        f"prop={match.group('prop')}",
                    ],
                    metadata={
                        "overlap_group": "props-state-sync",
                        "overlap_rank": 100,
                        "overlap_scope": f"{file_path}:{match.group('state')}",
                        "decision_profile": {
                            "controlled_uncontrolled_flip_signal": False,
                        },
                    },
                ),
            )
            if len(findings) >= max_findings:
                return findings

        props_tokens: set[str] = set()
        for fn_match in self._DESTRUCTURED_FN.finditer(text):
            raw = (fn_match.group("props1") or fn_match.group("props2") or "").strip()
            if not raw:
                continue
            for token in re.findall(r"[A-Za-z_]\w*", raw):
                if token not in {"children"}:
                    props_tokens.add(token)

        if not props_tokens:
            return findings

        for match in self._STATE_INIT_TOKEN.finditer(text):
            token = str(match.group("token") or "").strip()
            if token not in props_tokens:
                continue
            line = self._line_for_offset(text, match.start())
            findings.append(
                self.create_finding(
                    title="Props token copied into local state",
                    context=f"{file_path}:{line}:{match.group('state')}",
                    file=file_path,
                    line_start=line,
                    description=(
                        f"`useState({token})` likely mirrors a prop token into local state."
                    ),
                    why_it_matters=(
                        "Prop-to-state mirroring increases maintenance cost and stale-state risk."
                    ),
                    suggested_fix=(
                        "Prefer render-time derivation from props. If intentional, annotate why local divergence is required."
                    ),
                    confidence=0.84,
                    tags=["react", "state", "props"],
                    evidence_signals=[
                        "props_copy_signal=destructured_token",
                        f"token={token}",
                    ],
                    metadata={
                        "overlap_group": "props-state-sync",
                        "overlap_rank": 90,
                        "overlap_scope": f"{file_path}:{match.group('state')}",
                    },
                ),
            )
            if len(findings) >= max_findings:
                break
        return findings


class PropsStateSyncEffectSmellRule(_ReactGapAstRuleBase):
    id = "props-state-sync-effect-smell"
    name = "Props-State Sync Effect Smell"
    description = "Detects useEffect blocks that mirror props into state"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY

    _SETTER_CALL = re.compile(r"\b(set[A-Z][A-Za-z0-9_]*)\s*\(\s*(?P<expr>[^;]+)\s*\)\s*;", re.IGNORECASE)
    _STATE_SETTER_DECL = re.compile(
        r"const\s*\[\s*[A-Za-z_]\w*\s*,\s*(?P<setter>set[A-Z][A-Za-z0-9_]*)\s*\]\s*=\s*(?:React\.)?useState(?:<[^>]+>)?\s*\(",
        re.IGNORECASE,
    )
    _REDUCER_DISPATCH_DECL = re.compile(
        r"const\s*\[\s*[A-Za-z_]\w*\s*,\s*(?P<dispatch>[A-Za-z_]\w*)\s*\]\s*=\s*(?:React\.)?useReducer(?:<[^>]+>)?\s*\(",
        re.IGNORECASE,
    )
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Refactor the component code to remove the props-state sync effect smell pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 3
    group = 'React Stability'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = 'May be acceptable when the surrounding code is intentionally small-scope or the project has a documented exception.'
    detection_type = 'ast'
    analysis_cost = 'medium'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'props-state-sync'}

    def analyze_ast(
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
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 2)))
        state_updaters = {
            match.group("setter")
            for match in self._STATE_SETTER_DECL.finditer(text)
            if match.group("setter")
        }
        state_updaters.update(
            match.group("dispatch")
            for match in self._REDUCER_DISPATCH_DECL.finditer(text)
            if match.group("dispatch")
        )
        if not state_updaters:
            return []

        for effect in self._iter_effect_blocks(text):
            dep_tokens = [t for t in re.findall(r"[A-Za-z_]\w*", effect.deps) if t not in {"true", "false", "null"}]
            if not dep_tokens:
                continue
            setters = list(self._SETTER_CALL.finditer(effect.body))
            if len(setters) != 1:
                continue
            setter = setters[0].group(1)
            if setter not in state_updaters:
                continue
            expr = str(setters[0].group("expr") or "").strip()
            expr_low = expr.lower()
            if any(signal in expr_low for signal in ("fetch(", "axios.", "subscribe(", "addeventlistener(")):
                continue
            if not any(dep in expr for dep in dep_tokens):
                continue
            if ".map(" in expr or ".filter(" in expr or ".reduce(" in expr:
                continue
            findings.append(
                self.create_finding(
                    title="useEffect mirrors dependency into state",
                    context=f"{file_path}:{effect.line}:{setter}",
                    file=file_path,
                    line_start=effect.line,
                    description=(
                        "A `useEffect` with dependency array is writing mirrored state from the same dependency token."
                    ),
                    why_it_matters=(
                        "Effect-based state mirroring adds extra render churn and stale-sync edge cases."
                    ),
                    suggested_fix=(
                        "Compute derived value during render (or `useMemo` for expensive derivation) instead of syncing via `useEffect`."
                    ),
                    confidence=0.86,
                    tags=["react", "useeffect", "state-sync"],
                    evidence_signals=[
                        "props_state_sync=true",
                        f"deps={','.join(dep_tokens[:3])}",
                    ],
                    metadata={
                        "overlap_group": "props-state-sync",
                        "overlap_rank": 80,
                        "overlap_scope": f"{file_path}:{setter}",
                    },
                ),
            )
            if len(findings) >= max_findings:
                break
        return findings


class ControlledUncontrolledInputMismatchRule(_ReactGapAstRuleBase):
    id = "controlled-uncontrolled-input-mismatch"
    name = "Controlled/Uncontrolled Input Mismatch"
    description = "Detects React form controls that switch or violate controlled-input contracts"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.HIGH

    _CONTROL_TAGS = {"input", "textarea", "select"}
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Refactor the component code to remove the controlled/uncontrolled input mismatch pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 2
    group = 'Code Quality'
    applies_to = ['react-component', 'form']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'ast'
    analysis_cost = 'medium'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'controlled-uncontrolled-input'}

    def analyze_ast(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._skip_file(file_path) or not self._jsx.is_ready():
            return []
        tree = self._jsx.parse_tree(file_path, content or "")
        if not tree or not getattr(tree, "root_node", None):
            return []

        findings: list[Finding] = []
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 3)))
        cb = self._content_bytes(content or "")

        for node in self._jsx.iter_jsx_elements(tree.root_node):
            opening = self._jsx.get_opening_node(node)
            tag = self._jsx.get_tag_name(opening, cb).lower()
            if tag not in self._CONTROL_TAGS:
                continue
            attrs = self._attr_map(self._jsx.get_attributes(opening, cb))
            has_value = "value" in attrs or "checked" in attrs
            has_default = "defaultValue" in attrs or "defaultChecked" in attrs
            has_onchange = "onChange" in attrs
            is_readonly = "readOnly" in attrs or "disabled" in attrs
            if not has_value and not has_default:
                continue

            mismatch = ""
            confidence = 0.0
            if has_value and has_default:
                mismatch = "mixed_control_modes"
                confidence = 0.95
            elif has_value and not has_onchange and not is_readonly:
                mismatch = "controlled_without_onchange"
                confidence = 0.9

            if not mismatch:
                continue
            line = node.start_point.row + 1
            findings.append(
                self.create_finding(
                    title="Form control has controlled/uncontrolled mismatch",
                    context=f"{file_path}:{line}:{tag}",
                    file=file_path,
                    line_start=line,
                    description=(
                        "Form control appears to mix controlled/uncontrolled patterns or misses change handling."
                    ),
                    why_it_matters=(
                        "Mixed control modes cause React warnings and unpredictable input behavior."
                    ),
                    suggested_fix=(
                        "Use a single model per field: controlled (`value/checked` + `onChange`) or uncontrolled (`defaultValue/defaultChecked`)."
                    ),
                    confidence=confidence,
                    tags=["react", "forms", "input", "state"],
                    evidence_signals=[
                        f"controlled_uncontrolled_flip_signal={mismatch}",
                        f"tag={tag}",
                    ],
                    metadata={
                        "decision_profile": {
                            "controlled_uncontrolled_flip_signal": mismatch,
                        },
                    },
                ),
            )
            if len(findings) >= max_findings:
                break
        return findings


class UseMemoOveruseRule(_ReactGapAstRuleBase):
    id = "usememo-overuse"
    name = "useMemo Overuse"
    description = "Detects useMemo around trivial computations without measurable benefit"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.LOW
    default_classification = FindingClassification.ADVISORY

    _USEMEMO_BLOCK = re.compile(
        r"useMemo\s*\(\s*\(\)\s*=>\s*(?P<body>\{.*?\}|[^,]+)\s*,\s*\[(?P<deps>[^\]]*)\]\s*\)",
        re.IGNORECASE | re.DOTALL,
    )
    _EXPENSIVE_TOKENS = (".map(", ".filter(", ".reduce(", ".sort(", ".flatMap(", "JSON.parse(", "Object.entries(")
    _REFERENTIAL_SENSITIVE_TOKENS = (
        "clientSecret",
        "stripeOptions",
        "elementsOptions",
        "Elements",
        "loadStripe",
        "QueryClient",
        "queryClient",
        "RouterProvider",
        "ApolloProvider",
        "IntlProvider",
        "ThemeProvider",
    )
    severity_weight = 0
    confidence = 'low'
    fix_suggestion = 'Refactor the component code to remove the usememo overuse pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 4
    group = 'Code Quality'
    applies_to = ['react-component', 'hook']
    references = []
    related_rules = []
    false_positive_notes = 'This is a heuristic/style signal and may be acceptable when the team has an explicit convention for this pattern.'
    detection_type = 'ast'
    analysis_cost = 'medium'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'usememo-overuse'}

    def analyze_ast(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        text = content or ""
        findings: list[Finding] = []
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 2)))

        for match in self._USEMEMO_BLOCK.finditer(text):
            body = str(match.group("body") or "").strip()
            deps = [t for t in re.findall(r"[A-Za-z_]\w*", str(match.group("deps") or "")) if t not in {"true", "false"}]
            normalized = " ".join(body.split())
            if self._is_referentially_sensitive_memo(text, normalized, deps):
                continue
            if any(tok in normalized for tok in self._EXPENSIVE_TOKENS):
                continue
            if "new " in normalized or "for (" in normalized or "while (" in normalized:
                continue
            if len(normalized) > 80:
                continue
            if len(deps) > 2:
                continue
            line = self._line_for_offset(text, match.start())
            findings.append(
                self.create_finding(
                    title="useMemo appears unnecessary for trivial computation",
                    context=f"{file_path}:{line}:useMemo",
                    file=file_path,
                    line_start=line,
                    description="`useMemo` wraps a low-cost expression with weak memoization benefit.",
                    why_it_matters="Over-memoization adds indirection and dependency maintenance without improving runtime behavior.",
                    suggested_fix="Inline this computation in render. Keep `useMemo` for expensive or referentially-sensitive values.",
                    confidence=0.83,
                    tags=["react", "usememo", "performance", "maintainability"],
                    evidence_signals=[
                        "memoization_benefit_missing=true",
                        f"dependency_count={len(deps)}",
                    ],
                    metadata={
                        "decision_profile": {
                            "memoization_benefit_missing": True,
                        },
                    },
                ),
            )
            if len(findings) >= max_findings:
                break
        return findings

    def _is_referentially_sensitive_memo(self, text: str, normalized_body: str, deps: list[str]) -> bool:
        body = normalized_body.strip()
        if body.startswith("(") and body.endswith(")"):
            body = body[1:-1].strip()
        if not body.startswith("{"):
            return False
        if any(token in (text or "") for token in self._REFERENTIAL_SENSITIVE_TOKENS):
            return True
        return bool(any(dep.lower().endswith(("secret", "token", "key")) for dep in deps))


class UseCallbackOveruseRule(_ReactGapAstRuleBase):
    id = "usecallback-overuse"
    name = "useCallback Overuse"
    description = "Detects useCallback wrappers with little stability/perf benefit"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.LOW
    default_classification = FindingClassification.ADVISORY

    _USECALLBACK_BLOCK = re.compile(
        r"useCallback\s*\(\s*(?P<fn>\([^)]*\)\s*=>\s*(?:\{.*?\}|[^,]+))\s*,\s*\[(?P<deps>[^\]]*)\]\s*\)",
        re.IGNORECASE | re.DOTALL,
    )
    severity_weight = 0
    confidence = 'low'
    fix_suggestion = 'Refactor the component code to remove the usecallback overuse pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 4
    group = 'Code Quality'
    applies_to = ['react-component', 'hook']
    references = []
    related_rules = []
    false_positive_notes = 'This is a heuristic/style signal and may be acceptable when the team has an explicit convention for this pattern.'
    detection_type = 'ast'
    analysis_cost = 'medium'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'usecallback-overuse'}

    def analyze_ast(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        text = content or ""
        findings: list[Finding] = []
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 2)))
        for match in self._USECALLBACK_BLOCK.finditer(text):
            fn = str(match.group("fn") or "")
            deps = [t for t in re.findall(r"[A-Za-z_]\w*", str(match.group("deps") or "")) if t not in {"true", "false"}]
            fn_low = fn.lower()
            if "await " in fn_low or "fetch(" in fn_low or "axios." in fn_low:
                continue
            if "set" in fn and "=>" in fn and "prev" in fn:
                continue
            compact = " ".join(fn.split())
            if len(compact) > 90:
                continue
            if len(deps) > 1:
                continue
            line = self._line_for_offset(text, match.start())
            findings.append(
                self.create_finding(
                    title="useCallback appears unnecessary for trivial handler",
                    context=f"{file_path}:{line}:useCallback",
                    file=file_path,
                    line_start=line,
                    description="`useCallback` wraps a simple handler with limited evidence of memoization benefit.",
                    why_it_matters="Defensive `useCallback` usage increases code complexity and dependency churn.",
                    suggested_fix="Use a plain inline handler unless a measured render/stability problem requires memoization.",
                    confidence=0.81,
                    tags=["react", "usecallback", "performance", "maintainability"],
                    evidence_signals=[
                        "memoization_benefit_missing=true",
                        f"dependency_count={len(deps)}",
                    ],
                    metadata={
                        "decision_profile": {
                            "memoization_benefit_missing": True,
                        },
                    },
                ),
            )
            if len(findings) >= max_findings:
                break
        return findings


class ContextOversizedProviderRule(_ReactGapAstRuleBase):
    id = "context-oversized-provider"
    name = "Context Provider Oversized Value"
    description = "Detects broad provider values that likely trigger unnecessary fan-out rerenders"
    category = Category.PERFORMANCE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY

    _PROVIDER_VALUE = re.compile(
        r"<(?P<name>[A-Za-z_][A-Za-z0-9_.]*Provider)\b[^>]*\bvalue\s*=\s*\{\s*\{(?P<body>[^}]*)\}\s*\}",
        re.IGNORECASE | re.DOTALL,
    )
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Reduce the context provider oversized value by moving expensive work out of hot paths or adding the missing cache/query optimization. Keep the behavior identical and cover the faster path with a focused test.'
    examples = {}
    priority = 3
    group = 'React Performance'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'ast'
    analysis_cost = 'medium'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'performance', 'concern': 'context-oversized-provider'}

    def analyze_ast(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        text = content or ""
        max_keys = max(6, int(self.get_threshold("max_provider_keys_without_split", 6)))
        findings: list[Finding] = []

        for match in self._PROVIDER_VALUE.finditer(text):
            body = str(match.group("body") or "")
            keys = re.findall(r"([A-Za-z_]\w*)\s*:", body)
            if len(keys) < max_keys:
                continue
            line = self._line_for_offset(text, match.start())
            findings.append(
                self.create_finding(
                    title="Context provider value appears oversized",
                    context=f"{file_path}:{line}:{match.group('name')}",
                    file=file_path,
                    line_start=line,
                    description=(
                        "Provider `value` object includes many keys, which can increase broad tree rerenders."
                    ),
                    why_it_matters=(
                        "Large context payloads couple unrelated consumers and amplify rerender costs."
                    ),
                    suggested_fix=(
                        "Split context by concern or memoize/select value slices to reduce provider fan-out."
                    ),
                    confidence=0.82,
                    tags=["react", "context", "performance"],
                    evidence_signals=[
                        f"provider_key_count={len(keys)}",
                    ],
                ),
            )
        return findings[: max(1, int(self.get_threshold("max_findings_per_file", 2)))]


class LazyWithoutSuspenseRule(_ReactGapAstRuleBase):
    id = "lazy-without-suspense"
    name = "Lazy Component Without Suspense Boundary"
    description = "Detects lazy component usage without a Suspense boundary"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.HIGH

    _LAZY_DECL = re.compile(
        r"const\s+(?P<name>[A-Z][A-Za-z0-9_]*)\s*=\s*(?:React\.)?lazy\s*\(",
        re.IGNORECASE,
    )
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Refactor the component code to remove the lazy component without suspense boundary pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 2
    group = 'React Stability'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'ast'
    analysis_cost = 'medium'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'lazy-suspense'}

    def analyze_ast(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        text = content or ""
        lazy_components = [m.group("name") for m in self._LAZY_DECL.finditer(text)]
        if not lazy_components:
            return []
        if re.search(r"<(?:React\.)?Suspense\b", text):
            return []
        for name in lazy_components:
            if re.search(rf"<{re.escape(name)}\b", text):
                return [
                    self.create_finding(
                        title="Lazy component rendered without Suspense boundary",
                        context=f"{file_path}:{name}",
                        file=file_path,
                        line_start=1,
                        description=(
                            f"Detected lazy component `{name}` with no surrounding `<Suspense>` in this module."
                        ),
                        why_it_matters="Lazy components require Suspense to provide deterministic loading behavior.",
                        suggested_fix="Wrap lazy render paths with `<Suspense fallback={...}>`.",
                        confidence=0.9,
                        tags=["react", "lazy", "suspense"],
                        evidence_signals=[
                            "suspense_boundary_missing=true",
                            f"lazy_component={name}",
                        ],
                        metadata={
                            "decision_profile": {
                                "suspense_boundary_missing": True,
                            },
                        },
                    ),
                ]
        return []


class SuspenseFallbackMissingRule(_ReactGapAstRuleBase):
    id = "suspense-fallback-missing"
    name = "Suspense Fallback Missing"
    description = "Detects Suspense boundaries that do not define fallback UI"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM

    _SUSPENSE_OPEN = re.compile(r"<(?:React\.)?Suspense(?![^>]*\bfallback\s*=)[^>]*>", re.IGNORECASE)
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Refactor the component code to remove the suspense fallback missing pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 3
    group = 'React Stability'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'ast'
    analysis_cost = 'medium'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'suspense-fallback'}

    def analyze_ast(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        text = content or ""
        findings: list[Finding] = []
        for match in self._SUSPENSE_OPEN.finditer(text):
            line = self._line_for_offset(text, match.start())
            findings.append(
                self.create_finding(
                    title="Suspense boundary is missing fallback",
                    context=f"{file_path}:{line}:Suspense",
                    file=file_path,
                    line_start=line,
                    description="Suspense boundary found without a `fallback` prop.",
                    why_it_matters="Missing fallbacks create inconsistent loading states and poor user feedback.",
                    suggested_fix="Set a meaningful `fallback` UI for the Suspense boundary.",
                    confidence=0.92,
                    tags=["react", "suspense", "ux"],
                    evidence_signals=["suspense_boundary_missing=true"],
                    metadata={"decision_profile": {"suspense_boundary_missing": True}},
                ),
            )
        return findings[: max(1, int(self.get_threshold("max_findings_per_file", 2)))]


class StaleClosureInTimerRule(_ReactGapAstRuleBase):
    id = "stale-closure-in-timer"
    name = "Stale Closure In Timer Callback"
    description = "Detects timer callbacks capturing stale state in empty-deps effects"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM

    _STATE_DECL = re.compile(r"const\s*\[\s*(?P<state>[A-Za-z_]\w*)\s*,\s*set[A-Za-z_]\w*\s*\]\s*=\s*useState\s*\(", re.IGNORECASE)
    _TIMER_BLOCK = re.compile(
        r"(setTimeout|setInterval)\s*\(\s*(?:\(\)\s*=>\s*\{(?P<body1>.*?)\}|\(\)\s*=>\s*(?P<body2>[^,\n]+)|function\s*\([^)]*\)\s*\{(?P<body3>.*?)\})\s*,",
        re.IGNORECASE | re.DOTALL,
    )
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Refactor the component code to remove the stale closure in timer callback pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 3
    group = 'Code Quality'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'ast'
    analysis_cost = 'medium'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'stale-closure-in'}

    def analyze_ast(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        text = content or ""
        states = [m.group("state") for m in self._STATE_DECL.finditer(text)]
        if not states:
            return []
        findings: list[Finding] = []
        for effect in self._iter_effect_blocks(text):
            if effect.deps.replace(" ", "") != "":
                continue
            for timer in self._TIMER_BLOCK.finditer(effect.body):
                timer_body = str(timer.group("body1") or timer.group("body2") or timer.group("body3") or "")
                if "prev =>" in timer_body or "ref.current" in timer_body:
                    continue
                stale_refs = [s for s in states if re.search(rf"\b{re.escape(s)}\b", timer_body)]
                if not stale_refs:
                    continue
                findings.append(
                    self.create_finding(
                        title="Timer callback may capture stale state",
                        context=f"{file_path}:{effect.line}:{timer.group(1)}",
                        file=file_path,
                        line_start=effect.line,
                        description=(
                            "Timer callback inside `useEffect(..., [])` references state tokens directly."
                        ),
                        why_it_matters=(
                            "Empty-deps timers retain initial closure values and can run with stale data."
                        ),
                        suggested_fix=(
                            "Use functional state updates, refs, or include required dependencies in effect lifecycle."
                        ),
                        confidence=0.88,
                        tags=["react", "closure", "timer", "hooks"],
                        evidence_signals=[
                            "stale_closure_signal=timer",
                            f"state_refs={','.join(stale_refs[:3])}",
                        ],
                        metadata={"decision_profile": {"stale_closure_signal": "timer"}},
                    ),
                )
                if len(findings) >= max(1, int(self.get_threshold("max_findings_per_file", 2))):
                    return findings
        return findings


class StaleClosureInListenerRule(_ReactGapAstRuleBase):
    id = "stale-closure-in-listener"
    name = "Stale Closure In Event Listener"
    description = "Detects addEventListener callbacks capturing stale state in empty-deps effects"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM

    _STATE_DECL = re.compile(r"const\s*\[\s*(?P<state>[A-Za-z_]\w*)\s*,\s*set[A-Za-z_]\w*\s*\]\s*=\s*useState\s*\(", re.IGNORECASE)
    _LISTENER_BLOCK = re.compile(
        r"addEventListener\s*\(\s*['\"][^'\"]+['\"]\s*,\s*(?:\([^)]*\)\s*=>\s*\{(?P<body1>.*?)\}|\([^)]*\)\s*=>\s*(?P<body2>[^)\n]+)|function\s*\([^)]*\)\s*\{(?P<body3>.*?)\})\s*\)",
        re.IGNORECASE | re.DOTALL,
    )
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Refactor the component code to remove the stale closure in event listener pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 3
    group = 'Queue & Jobs'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'ast'
    analysis_cost = 'medium'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'stale-closure-in'}

    def analyze_ast(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        text = content or ""
        states = [m.group("state") for m in self._STATE_DECL.finditer(text)]
        if not states:
            return []

        findings: list[Finding] = []
        for effect in self._iter_effect_blocks(text):
            if effect.deps.replace(" ", "") != "":
                continue
            for listener in self._LISTENER_BLOCK.finditer(effect.body):
                body = str(listener.group("body1") or listener.group("body2") or listener.group("body3") or "")
                if "ref.current" in body or "setState((prev" in body:
                    continue
                stale_refs = [s for s in states if re.search(rf"\b{re.escape(s)}\b", body)]
                if not stale_refs:
                    continue
                findings.append(
                    self.create_finding(
                        title="Event listener may capture stale state",
                        context=f"{file_path}:{effect.line}:addEventListener",
                        file=file_path,
                        line_start=effect.line,
                        description="Listener callback in `useEffect(..., [])` references state without refresh path.",
                        why_it_matters="Listeners with stale closures can dispatch incorrect state-dependent behavior.",
                        suggested_fix="Use refs or re-register listener with dependency-safe callback wiring.",
                        confidence=0.86,
                        tags=["react", "closure", "listener", "hooks"],
                        evidence_signals=[
                            "stale_closure_signal=listener",
                            f"state_refs={','.join(stale_refs[:3])}",
                        ],
                        metadata={"decision_profile": {"stale_closure_signal": "listener"}},
                    ),
                )
                if len(findings) >= max(1, int(self.get_threshold("max_findings_per_file", 2))):
                    return findings
        return findings


class DuplicateKeySourceRule(_ReactGapAstRuleBase):
    id = "duplicate-key-source"
    name = "Potential Duplicate Key Source"
    description = "Detects list keys derived from weak/non-unique fields"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM

    _KEY_EXPR = re.compile(r"key=\{(?P<expr>[^}]+)\}", re.IGNORECASE)
    _PURE_WEAK_KEY = re.compile(r"^\s*(?P<var>[A-Za-z_][A-Za-z0-9_\.]*)\.(?P<field>label|name|title)\s*$", re.IGNORECASE)
    _COMPOSITE_KEY = re.compile(r"[\$\{].*\+|template|concat|replace", re.IGNORECASE)
    _MAP_SIGNAL = re.compile(r"\.map\s*\(", re.IGNORECASE)
    _MAP_CALLBACK_START = re.compile(
        r"(?P<source>[A-Za-z_][A-Za-z0-9_\.]*)\.map\s*\(\s*\(?\s*(?P<item>[A-Za-z_][A-Za-z0-9_]*)",
        re.IGNORECASE,
    )
    _INDEX_IN_KEY = re.compile(r"\b(idx|i|index|itemIdx)\b", re.IGNORECASE)
    _INDEX_ONLY_USAGE = re.compile(r"\b(idx|i|index|itemIdx)\s*===?\s*\d+", re.IGNORECASE)
    _STATIC_ARRAY_DECL_TEMPLATE = r"(?:const|let)\s+{name}\s*=\s*\["
    _PREDEFINED_CONSTANT = re.compile(r"\b(?:const|let|var)\s+(?P<name>[A-Z][A-Z_]+)\s*=\s*\[", re.IGNORECASE)
    _PRESENTATION_COLLECTION_NAMES = {
        "actions",
        "breadcrumbs",
        "checks",
        "crumbs",
        "features",
        "filters",
        "kpis",
        "metrics",
        "options",
        "quicklinks",
        "sections",
        "stats",
        "steps",
        "tabs",
    }
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Refactor the component code to remove the potential duplicate key source pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 3
    group = 'React Stability'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'cross-file'
    analysis_cost = 'high'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'duplicate-key-source'}

    def analyze_ast(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        text = content or ""
        if not self._MAP_SIGNAL.search(text):
            return []

        # Extract predefined constants (STEPS, KPIS, etc.) from file
        predefined_constants = self._extract_predefined_constants(text)

        findings: list[Finding] = []
        for match in self._KEY_EXPR.finditer(text):
            expr = str(match.group("expr") or "").strip()
            key_offset = match.start()

            # Skip composite keys (e.g., `step-${s.label}`, `kpi-${idx}-${label}`)
            if self._is_composite_key(expr):
                continue

            weak_match = self._PURE_WEAK_KEY.match(expr)
            if not weak_match:
                continue

            var_name = weak_match.group("var").split(".")[-1]
            weak_match.group("var").split(".")[0]
            source = self._map_source_for_key(text, key_offset, var_name)

            # Skip if source is a predefined constant (STEPS, KPIS, etc.)
            source_tail = source.split(".")[-1] if source else ""
            if source_tail in predefined_constants:
                continue

            if self._is_stable_presentation_collection(text, source):
                continue

            # Check if index is used in the key expression
            if self._is_index_used_safely(text, key_offset, expr):
                continue

            key_field = weak_match.group("field")
            if re.search(r"\.(id|uuid|public_id)\b", expr, re.IGNORECASE):
                continue

            line = self._line_for_offset(text, key_offset)
            findings.append(
                self.create_finding(
                    title="List key may use non-unique field",
                    context=f"{file_path}:{line}:{key_field}",
                    file=file_path,
                    line_start=line,
                    description=f"Key uses `{key_field}`, which is often not globally unique across collections.",
                    why_it_matters="Weak keys degrade reconciliation stability and can cause rendering bugs.",
                    suggested_fix="Prefer stable unique IDs (id/uuid/public_id) or composite keys (index + field) for list keys.",
                    confidence=0.75,
                    tags=["react", "keys", "rendering"],
                    evidence_signals=[f"key_field={key_field}"],
                    metadata={
                        "overlap_group": "list-key-stability",
                        "overlap_rank": 70,
                        "overlap_scope": f"{file_path}:{line}",
                    },
                ),
            )
        return findings[: max(1, int(self.get_threshold("max_findings_per_file", 2)))]

    def _extract_predefined_constants(self, text: str) -> set[str]:
        """Extract UPPER_CASE constant arrays defined in the file (STEPS, KPIS, etc.)"""
        return {m.group("name") for m in self._PREDEFINED_CONSTANT.finditer(text)}

    def _is_composite_key(self, expr: str) -> bool:
        """Check if key is a composite/template literal with transformations."""
        # Template literals with transformations: `step-${s.label.replace(...)}`
        if self._COMPOSITE_KEY.search(expr):
            return True
        # Contains string interpolation with multiple parts
        return bool("${" in expr and ("+" in expr or "-" in expr or "_" in expr))

    def _is_index_used_safely(self, text: str, key_offset: int, key_expr: str) -> bool:
        """
        Check if index parameter is used safely (not as the sole key source).
        Returns True if index is only used for non-key purposes (styling, conditional logic).
        """
        # Find the map callback that contains this key
        window = (text or "")[: max(0, key_offset)]

        # Check if this map callback has an index parameter (e.g., .map((kpi, idx) => ...))
        # Look for patterns like: array.map((item, idx) => ...) or array.map((item, i) => ...)
        map_with_index = re.search(
            r"\.map\s*\(\s*\(?\s*[A-Za-z_][A-Za-z0-9_]*\s*,\s*(?P<idx>idx|i|index|itemIdx)\b",
            window,
            re.IGNORECASE,
        )

        if not map_with_index:
            # No index parameter in the map callback - check key normally
            return False

        idx_param = map_with_index.group("idx")

        # If index is in the key expression, check if it's a composite key
        if re.search(rf"\b{re.escape(idx_param)}\b", key_expr, re.IGNORECASE):
            # Index IS used in key - check if it's composite (safe)
            # e.g., `key={`kpi-${idx}-${kpi.label}`}` is safe
            return self._is_composite_key(key_expr)

        # Index exists in callback but is NOT used in key expression
        # This means it's used for styling/conditional logic only - skip the warning
        # e.g., kpis.map((kpi, idx) => (... color={idx === 0 ? ...} key={kpi.label} ...))
        return True

    def _map_source_for_key(self, text: str, key_offset: int, item_var: str) -> str:
        source = ""
        window = (text or "")[: max(0, key_offset)]
        for match in self._MAP_CALLBACK_START.finditer(window):
            if match.group("item") == item_var:
                source = str(match.group("source") or "")
        return source

    def _is_stable_presentation_collection(self, text: str, source: str) -> bool:
        if not source:
            return False
        source_tail = source.split(".")[-1]
        if source_tail.isupper() and len(source_tail) > 1:
            return True
        if source_tail.lower() in self._PRESENTATION_COLLECTION_NAMES:
            return True
        declaration = self._STATIC_ARRAY_DECL_TEMPLATE.format(name=re.escape(source_tail))
        return bool(re.search(declaration, text or "", re.IGNORECASE))


class MissingLoadingStateRule(_ReactGapAstRuleBase):
    id = "missing-loading-state"
    name = "Missing Loading State"
    description = "Detects async page surfaces without explicit loading UI"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.LOW
    default_classification = FindingClassification.ADVISORY

    # Only query hooks establish a page-owned loading contract that this local
    # rule can verify. Event-handler requests and Inertia router.reload use
    # application/global progress behavior and are not proof of missing UI.
    _ASYNC_SIGNAL = re.compile(r"\b(useQuery|useInfiniteQuery|useSWR)\s*\(", re.IGNORECASE)
    _LOADING_SIGNAL = re.compile(r"\b(isLoading|loading|pending|skeleton|spinner)\b", re.IGNORECASE)
    severity_weight = 0
    confidence = 'low'
    fix_suggestion = 'Refactor the component code to remove the missing loading state pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 4
    group = 'React Stability'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = 'This is a heuristic/style signal and may be acceptable when the team has an explicit convention for this pattern.'
    detection_type = 'ast'
    analysis_cost = 'medium'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'loading-state'}

    def analyze_ast(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if self._skip_file(file_path) or not self._is_page_like(file_path):
            return []
        text = content or ""
        if self._looks_like_child_composition(file_path, text):
            return []
        if not self._ASYNC_SIGNAL.search(text):
            return []
        if self._LOADING_SIGNAL.search(text):
            return []
        async_match = self._ASYNC_SIGNAL.search(text)
        line = self._line_for_offset(text, async_match.start()) if async_match else 1
        return [
            self.create_finding(
                title="Async page flow missing explicit loading state",
                context=f"{file_path}:loading-state",
                file=file_path,
                line_start=line,
                description="Async data signals were found but no explicit loading/pending UI branch was detected.",
                why_it_matters="Missing loading states can produce blank, confusing, or flickering first paint behavior.",
                suggested_fix="Add an explicit loading/pending branch near primary async surface rendering.",
                confidence=0.72,
                tags=["react", "ux", "async"],
                evidence_signals=[
                    "query_hook_surface=true",
                    "page_owns_pending_state=true",
                    "loading_branch_missing=true",
                ],
            ),
        ]


class MissingEmptyStateRule(_ReactGapAstRuleBase):
    id = "missing-empty-state"
    name = "Missing Empty State"
    description = "Detects list-heavy page surfaces without explicit empty-state handling"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.LOW
    default_classification = FindingClassification.ADVISORY

    _LIST_SIGNAL = re.compile(r"\.map\s*\(", re.IGNORECASE)
    _EMPTY_SIGNAL = re.compile(r"(length\s*===\s*0|!+\s*\w+\.length|\bempty\b|No\s+[A-Za-z]+)", re.IGNORECASE)
    _MAP_VAR = re.compile(r"\b(?P<var>[A-Za-z_]\w*)\.map\s*\(", re.IGNORECASE)
    # Detect inline array literals being mapped: [1,2,3].map(...) or [{...}].map(...)
    _INLINE_ARRAY_MAP = re.compile(r"\[\s*[^\]]+\]\s*\.map\s*\(", re.IGNORECASE)
    severity_weight = 0
    confidence = 'low'
    fix_suggestion = 'Refactor the component code to remove the missing empty state pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 4
    group = 'React Stability'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = 'This is a heuristic/style signal and may be acceptable when the team has an explicit convention for this pattern.'
    detection_type = 'ast'
    analysis_cost = 'medium'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'empty-state'}

    def analyze_ast(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if self._skip_file(file_path) or not self._is_page_like(file_path):
            return []
        if self._is_non_render_module(file_path):
            return []
        text = content or ""
        if self._looks_like_child_composition(file_path, text):
            return []
        if not self._looks_like_render_module(text):
            return []
        if not self._LIST_SIGNAL.search(text):
            return []

        # Count all .map() calls vs inline array .map() calls
        all_map_calls = list(self._LIST_SIGNAL.finditer(text))
        inline_array_maps = list(self._INLINE_ARRAY_MAP.finditer(text))

        # If all .map() calls are on inline array literals, skip (static data, cannot be empty)
        if inline_array_maps and len(inline_array_maps) == len(all_map_calls):
            return []

        map_vars = {m.group("var") for m in self._MAP_VAR.finditer(text) if m.group("var")}
        if not map_vars:
            # A method-chain or generated presentation map does not identify a
            # page-owned result collection strongly enough to demand an empty
            # state from this file.
            return []
        guarded_vars: set[str] = set()
        for var in map_vars:
            escaped = re.escape(var)
            length = rf"\b{escaped}\s*\?*\.\s*length"
            if re.search(rf"{length}\s*(?:>\s*0|>=\s*1)\s*(?:&&|\?)", text):
                guarded_vars.add(var)
            if re.search(rf"if\s*\(\s*!\s*{length}\s*\)", text):
                guarded_vars.add(var)
            if re.search(rf"{length}\s*(?:===?\s*0|<=\s*0)", text):
                guarded_vars.add(var)
            if re.search(rf"(?:const|let)\s+{escaped}\s*=\s*\[", text):
                # Static literal lists do not need a runtime empty-state branch.
                guarded_vars.add(var)
        dynamic_vars = sorted(map_vars - guarded_vars)
        if not dynamic_vars:
            return []

        if self._EMPTY_SIGNAL.search(text):
            return []
        first_map = next(
            (match for match in self._MAP_VAR.finditer(text) if match.group("var") in dynamic_vars),
            None,
        )
        line = self._line_for_offset(text, first_map.start()) if first_map else 1
        return [
            self.create_finding(
                title="List rendering missing explicit empty state",
                context=f"{file_path}:empty-state",
                file=file_path,
                line_start=line,
                description=(
                    "Dynamic result collection(s) are rendered without an explicit empty-result branch: "
                    + ", ".join(dynamic_vars[:4])
                    + "."
                ),
                why_it_matters="Empty-state handling improves clarity and prevents confusing blank states.",
                suggested_fix="Add a clear empty-state branch when collection length is zero.",
                confidence=0.74,
                tags=["react", "ux", "lists"],
                evidence_signals=[
                    "empty_state_missing=true",
                    "dynamic_collection_render=true",
                    f"collections={','.join(dynamic_vars[:6])}",
                ],
            ),
        ]


class RefAccessDuringRenderRule(_ReactGapAstRuleBase):
    id = "ref-access-during-render"
    name = "Ref Access During Render"
    description = "Detects `.current` reads directly inside JSX render expressions"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    _REF_DECL = re.compile(
        r"\bconst\s+(?P<name>[A-Za-z_]\w*)\s*=\s*(?:React\.)?useRef\s*\(",
        re.IGNORECASE,
    )
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Refactor the component code to remove the ref access during render pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 3
    group = 'React Stability'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'ast'
    analysis_cost = 'medium'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'ref-access-during'}

    def analyze_ast(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        text = content or ""
        ref_names = {m.group("name") for m in self._REF_DECL.finditer(text) if m.group("name")}
        if not ref_names:
            return []
        if not self._jsx.is_ready():
            return []
        tree = self._jsx.parse_tree(file_path, text)
        if not tree or not getattr(tree, "root_node", None):
            return []

        findings: list[Finding] = []
        cb = self._content_bytes(text)
        for node in self._jsx.walk(tree.root_node):
            if getattr(node, "type", "") != "jsx_expression":
                continue
            snippet = self._node_text(node, cb)
            matched_ref = None
            for ref_name in ref_names:
                if f"{ref_name}.current" in snippet or re.search(
                    rf"\b{re.escape(ref_name)}\?\.\s*current\b",
                    snippet,
                ):
                    matched_ref = ref_name
                    break
            if not matched_ref:
                continue
            if re.search(rf"\b{re.escape(matched_ref)}\.current\?\.(focus|click)\b", snippet):
                continue
            line = node.start_point.row + 1
            findings.append(
                self.create_finding(
                    title="Ref current is read during render",
                    context=f"{file_path}:{line}:ref-current:{matched_ref}",
                    file=file_path,
                    line_start=line,
                    description="`ref.current` appears in JSX render expression, coupling render output to mutable ref state.",
                    why_it_matters="Refs are mutable containers and do not trigger render updates predictably.",
                    suggested_fix="Move this value to state/derived data when UI output depends on it.",
                    confidence=0.88,
                    tags=["react", "refs", "render"],
                    evidence_signals=["ref_render_access=true"],
                ),
            )
        return findings[: max(1, int(self.get_threshold("max_findings_per_file", 2)))]


class RefUsedAsReactiveStateRule(_ReactGapAstRuleBase):
    id = "ref-used-as-reactive-state"
    name = "Ref Used as Reactive State"
    description = "Detects refs used as primary reactive state instead of useState"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM

    _REF_WRITE = re.compile(r"\b([A-Za-z_]\w*)\.current\s*=", re.IGNORECASE)
    _REF_READ = re.compile(r"\b([A-Za-z_]\w*)\.current\b(?!\s*=)", re.IGNORECASE)
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Refactor the component code to remove the ref used as reactive state pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 3
    group = 'React Stability'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'ast'
    analysis_cost = 'medium'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'ref-used-as'}

    def analyze_ast(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        text = content or ""
        writes = [m.group(1) for m in self._REF_WRITE.finditer(text)]
        if not writes:
            return []
        if "useState(" in text:
            return []
        if not self._jsx.is_ready():
            return []
        tree = self._jsx.parse_tree(file_path, text)
        if not tree or not getattr(tree, "root_node", None):
            return []

        cb = self._content_bytes(text)
        render_reads: set[str] = set()
        for node in self._jsx.walk(tree.root_node):
            if getattr(node, "type", "") != "jsx_expression":
                continue
            snippet = self._node_text(node, cb)
            for ref_name in writes:
                if f"{ref_name}.current" in snippet or re.search(rf"\b{re.escape(ref_name)}\?\.\s*current\b", snippet):
                    render_reads.add(ref_name)

        shared = sorted(set(writes).intersection(render_reads))
        if not shared:
            return []

        return [
            self.create_finding(
                title="Ref appears to be used as reactive UI state",
                context=f"{file_path}:{shared[0]}",
                file=file_path,
                line_start=1,
                description=(
                    "Ref is written and read as if it drives UI state without corresponding `useState` signal."
                ),
                why_it_matters=(
                    "Using refs as reactive state bypasses React update flow and can produce stale UI."
                ),
                suggested_fix="Use `useState` (or reducer) for render-driving values and keep refs for imperative handles.",
                confidence=0.8,
                tags=["react", "refs", "state"],
                evidence_signals=[f"reactive_ref_candidates={','.join(shared[:3])}"],
            ),
        ]
