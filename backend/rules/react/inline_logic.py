"""
Inline Logic Rule
Detects API calls and complex logic directly in React components.
"""
import re
import os
from pathlib import Path
from schemas.facts import Facts, ReactComponentInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule
from core.path_utils import normalize_rel_path


class InlineLogicRule(Rule):
    """
    Detects inline API calls and business logic in React components.
    
    Logic should be extracted to:
    - Custom hooks for reusable state/effects
    - Service modules for API calls
    - Utility functions for transformations
    """
    
    id = "inline-api-logic"
    name = "Inline API Logic Detection"
    description = "Detects API calls and logic in component bodies"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    # Run whenever React components were detected (facts.react_components),
    # regardless of detected project type (some repos don't have package.json at root).
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Detects nested setState-like calls inside handlers:
    # e.g. `setPrev(prev => ({ ...prev, nested: { ...prev.nested, key: val } }))`
    _NESTED_SETTER = re.compile(
        r"set[A-Z][a-zA-Z0-9]*\s*\(\s*(?:[a-zA-Z_]+\s*=>\s*)?\(\s*\{[^}]{0,400}\.\.\."
        r"[a-zA-Z_][a-zA-Z0-9_.]*[^}]{0,400}\}\s*\)",
        re.DOTALL,
    )
    _USE_STATE = re.compile(r"\buseState\s*[<(]")
    _PAGE_OR_SHELL_PATH_MARKERS = ("/pages/", "/page/", "/screens/", "/screen/", "/views/", "/view/")
    _LOCAL_UI_IMPORT_MARKERS = (
        "./",
        "../",
        "/components/",
        "/component/",
        "/widgets/",
        "/widget/",
        "/modals/",
        "/panels/",
        "/sections/",
        "@/components",
        "@/widgets",
        "@/pages",
        "@/screens",
        "@/views",
        "@/features",
    )
    _API_SIDE_EFFECT_PATTERN = re.compile(r"\b(fetch\s*\(|axios\.)", re.IGNORECASE)
    _QUERY_HOOK_PATTERN = re.compile(r"\b(useQuery|useSWR)\s*\(", re.IGNORECASE)
    _SERVICE_IMPORT_MARKERS = ("/services/", "/api/", "service", "client", "repository")
    
    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings = []
        min_state_hook_count = max(3, int(self.get_threshold("min_state_hook_count", 4)))
        suppress_query_hook_usage = bool(self.get_threshold("suppress_query_hook_usage", True))
        require_fetch_or_axios_for_api_finding = bool(
            self.get_threshold("require_fetch_or_axios_for_api_finding", True)
        )

        for component in facts.react_components:
            if self._is_hook_module(component.file_path, component.name):
                continue
            if component.has_api_calls:
                api_profile = self._api_profile(component, facts)
                if suppress_query_hook_usage and api_profile["suppressed_as_query_hook_only"]:
                    continue
                if require_fetch_or_axios_for_api_finding and not api_profile["has_direct_fetch_or_axios"]:
                    continue
                if api_profile["suppressed_as_orchestrator_shell"]:
                    continue
                findings.append(self._create_api_finding(component, api_profile))
            
            if component.has_inline_state_logic:
                logic_profile = self._logic_profile(component, facts)
                if logic_profile["suppressed_as_composed_shell"]:
                    continue
                if logic_profile["state_hook_count"] < min_state_hook_count:
                    continue
                findings.append(self._create_logic_finding(component, logic_profile))
        
        return findings

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        """Supplement AST analysis: catch complex nested state updates in handlers.

        Catches components with 2-3 useState calls (below the AST threshold) that
        contain deeply nested spread-based state updates inside JSX handlers —
        a clear signal the logic belongs in a custom hook.
        """
        findings: list[Finding] = []
        if self._is_hook_module(file_path, os.path.splitext(os.path.basename(file_path))[0]):
            return []
        state_count = len(self._USE_STATE.findall(content))
        if state_count < 2:
            return []

        nested_setters = self._NESTED_SETTER.findall(content)
        if not nested_setters:
            return []

        # Only flag if meaningful complexity
        if len(nested_setters) < 2 and state_count < 3:
            return []

        start = content.find(nested_setters[0])
        line_num = content.count("\n", 0, max(0, start)) + 1 if start >= 0 else 1
        comp_name = os.path.splitext(os.path.basename(file_path))[0]

        findings.append(
            self.create_finding(
                title="Complex nested state updates in component handlers",
                context=f"{file_path}:{line_num}:nested-state-update",
                file=file_path,
                line_start=line_num,
                description=(
                    f"Found {len(nested_setters)} deeply nested state setter(s) with spread operators "
                    f"in `{comp_name}`. Extract this complexity into a custom hook."
                ),
                why_it_matters=(
                    "Deeply nested spread-based state updates inside JSX handlers make components hard to read "
                    "and test. Extracting to a custom hook centralises all state transitions in one "
                    "testable place and keeps the component focused on rendering."
                ),
                suggested_fix=(
                    f"Create `use{comp_name}State()` or `use{comp_name}Form()` and move the state variables "
                    "and their update logic into it. Return only the values the component needs to render."
                ),
                tags=["react", "hooks", "state-management", "srp", "separation-of-concerns"],
                confidence=0.80,
                evidence_signals=[
                    f"nested_setters={len(nested_setters)}",
                    f"state_count={state_count}",
                ],
            )
        )
        return findings

    def _is_hook_module(self, file_path: str | None, component_name: str | None) -> bool:
        norm_path = str(file_path or "").replace("\\", "/")
        norm_low = norm_path.lower()
        name = str(component_name or "")
        base_name = os.path.splitext(os.path.basename(norm_path))[0]
        return (
            "/hooks/" in norm_low
            or bool(re.match(r"^use[A-Z]", name))
            or bool(re.match(r"^use[A-Z]", base_name))
        )

    def _component_imports(self, component: ReactComponentInfo, facts: Facts) -> list[str]:
        imports = [str(imp or "") for imp in (component.imports or []) if str(imp or "").strip()]
        if imports:
            return imports

        graph = getattr(facts, "_frontend_symbol_graph", None)
        files_map = graph.get("files", {}) if isinstance(graph, dict) else {}
        payload = files_map.get(normalize_rel_path(str(component.file_path or "")))
        if not isinstance(payload, dict):
            return []
        return [str(imp or "") for imp in (payload.get("imports", []) or []) if str(imp or "").strip()]

    def _source_text(self, component: ReactComponentInfo, facts: Facts) -> str:
        rel_path = normalize_rel_path(str(component.file_path or ""))
        if not rel_path:
            return ""
        root = Path(str(getattr(facts, "project_path", "") or "."))
        try:
            return (root / rel_path).read_text(encoding="utf-8", errors="replace")
        except Exception:
            return ""

    def _is_composed_shell(self, component: ReactComponentInfo, facts: Facts) -> bool:
        path = str(component.file_path or "").replace("\\", "/").lower()
        imports = [str(imp or "").lower().replace("\\", "/") for imp in self._component_imports(component, facts)]
        has_custom_hook_import = any("/hooks/" in imp or "/use" in imp for imp in imports)
        local_component_imports = sum(
            1 for imp in imports if any(marker in imp for marker in self._LOCAL_UI_IMPORT_MARKERS)
        )
        is_page_shell = any(marker in path for marker in self._PAGE_OR_SHELL_PATH_MARKERS) or str(component.name or "").endswith(("Page", "Screen", "View"))
        return is_page_shell and has_custom_hook_import and local_component_imports >= 2

    def _api_profile(self, component: ReactComponentInfo, facts: Facts) -> dict[str, object]:
        source = self._source_text(component, facts)
        imports = [str(imp or "").lower().replace("\\", "/") for imp in self._component_imports(component, facts)]
        has_direct_fetch_or_axios = bool(self._API_SIDE_EFFECT_PATTERN.search(source))
        has_query_hook_usage = bool(self._QUERY_HOOK_PATTERN.search(source))
        has_custom_hook_import = any("/hooks/" in imp or "/use" in imp for imp in imports)
        has_service_import = any(
            marker in imp
            for imp in imports
            for marker in self._SERVICE_IMPORT_MARKERS
        )
        local_component_imports = sum(
            1 for imp in imports if any(marker in imp for marker in self._LOCAL_UI_IMPORT_MARKERS)
        )
        suppressed_as_query_hook_only = has_query_hook_usage and not has_direct_fetch_or_axios
        suppressed_as_orchestrator_shell = (
            self._is_composed_shell(component, facts)
            and has_custom_hook_import
            and has_service_import
            and not has_direct_fetch_or_axios
            and local_component_imports >= 2
        )
        return {
            "has_direct_fetch_or_axios": has_direct_fetch_or_axios,
            "has_query_hook_usage": has_query_hook_usage,
            "has_custom_hook_import": has_custom_hook_import,
            "has_service_import": has_service_import,
            "local_component_imports": local_component_imports,
            "suppressed_as_query_hook_only": suppressed_as_query_hook_only,
            "suppressed_as_orchestrator_shell": suppressed_as_orchestrator_shell,
            "evidence_signals": [
                f"direct_fetch_or_axios={int(has_direct_fetch_or_axios)}",
                f"query_hooks={int(has_query_hook_usage)}",
                f"custom_hook_import={int(has_custom_hook_import)}",
                f"service_import={int(has_service_import)}",
                f"local_components={local_component_imports}",
                f"suppressed_query_only={int(suppressed_as_query_hook_only)}",
                f"suppressed_shell={int(suppressed_as_orchestrator_shell)}",
            ],
        }

    def _logic_profile(self, component: ReactComponentInfo, facts: Facts) -> dict[str, object]:
        hooks = [str(h or "") for h in (component.hooks_used or [])]
        state_hook_count = sum(1 for h in hooks if h in {"useState", "useReducer", "useEffect", "useMemo", "useCallback"})
        composed_shell = self._is_composed_shell(component, facts)
        return {
            "state_hook_count": state_hook_count,
            "suppressed_as_composed_shell": composed_shell,
            "evidence_signals": [
                f"state_hooks={state_hook_count}",
                f"composed_shell={int(composed_shell)}",
            ],
        }

    def _create_api_finding(self, component: ReactComponentInfo, profile: dict[str, object]) -> Finding:
        """Create finding for inline API calls."""
        return self.create_finding(
            title="Inline API call in React component",
            file=component.file_path,
            line_start=component.line_start,
            context=component.name,
            description=(
                f"Component `{component.name}` contains direct API calls. "
                f"Extract to a custom hook or service module."
            ),
            why_it_matters=(
                "Inline API calls make components harder to test and reuse. "
                "They mix data fetching with presentation, violating separation of concerns. "
                "Custom hooks make the same logic reusable across components."
            ),
            suggested_fix=(
                f"1. Create a custom hook like `use{component.name}Data()`\n"
                "2. Move fetch logic into the hook\n"
                "3. Return data, loading, and error states\n"
                "4. Use React Query or SWR for caching"
            ),
            code_example=self._generate_hook_example(component.name),
            tags=["react", "hooks", "api", "separation-of-concerns"],
            evidence_signals=profile["evidence_signals"],
            metadata={"decision_profile": profile},
        )
    
    def _create_logic_finding(self, component: ReactComponentInfo, profile: dict[str, object]) -> Finding:
        """Create finding for inline state logic."""
        return self.create_finding(
            title="Complex state logic in React component",
            file=component.file_path,
            line_start=component.line_start,
            context=component.name,
            description=(
                f"Component `{component.name}` has complex inline state logic. "
                f"Consider extracting to a custom hook."
            ),
            why_it_matters=(
                "Complex state logic in components makes them hard to follow. "
                "Custom hooks encapsulate related state and effects, "
                "making components focused on rendering."
            ),
            suggested_fix=(
                "1. Identify related state variables and effects\n"
                "2. Extract to a custom hook\n"
                "3. Return only what the component needs\n"
                "4. Give the hook a descriptive name"
            ),
            code_example=self._generate_state_example(component.name),
            tags=["react", "hooks", "state-management"],
            evidence_signals=profile["evidence_signals"],
            metadata={"decision_profile": profile},
        )
    
    def _generate_hook_example(self, name: str) -> str:
        """Generate hook extraction example."""
        return f"""// Before (API call in component)
function {name}() {{
    const [data, setData] = useState(null);
    
    useEffect(() => {{
        fetch('/api/data')
            .then(res => res.json())
            .then(setData);
    }}, []);
    
    return <div>{{data?.name}}</div>;
}}

// After (extracted to hook)
function use{name}Data() {{
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    
    useEffect(() => {{
        fetch('/api/data')
            .then(res => res.json())
            .then(setData)
            .catch(setError)
            .finally(() => setLoading(false));
    }}, []);
    
    return {{ data, loading, error }};
}}

function {name}() {{
    const {{ data, loading, error }} = use{name}Data();
    
    if (loading) return <Spinner />;
    if (error) return <Error error={{error}} />;
    return <div>{{data?.name}}</div>;
}}"""
    
    def _generate_state_example(self, name: str) -> str:
        """Generate state logic extraction example."""
        return f"""// Before (complex logic in component)
function {name}() {{
    const [items, setItems] = useState([]);
    const [filter, setFilter] = useState('');
    const [sortBy, setSortBy] = useState('name');
    
    const filteredItems = useMemo(() => {{
        return items
            .filter(i => i.name.includes(filter))
            .sort((a, b) => a[sortBy] > b[sortBy] ? 1 : -1);
    }}, [items, filter, sortBy]);
    
    // ... more logic
}}

// After (extracted to custom hook)
function use{name}List(initialItems) {{
    const [items, setItems] = useState(initialItems);
    const [filter, setFilter] = useState('');
    const [sortBy, setSortBy] = useState('name');
    
    const filteredItems = useMemo(() => {{
        return items
            .filter(i => i.name.includes(filter))
            .sort((a, b) => a[sortBy] > b[sortBy] ? 1 : -1);
    }}, [items, filter, sortBy]);
    
    return {{ filteredItems, filter, setFilter, sortBy, setSortBy }};
}}

function {name}() {{
    const list = use{name}List(data);
    return <ItemList {{...list}} />;
}}"""
