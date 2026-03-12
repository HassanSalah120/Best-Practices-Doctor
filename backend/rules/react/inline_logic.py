"""
Inline Logic Rule
Detects API calls and complex logic directly in React components.
"""
import re
import os
from schemas.facts import Facts, ReactComponentInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


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
    
    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings = []
        
        for component in facts.react_components:
            if component.has_api_calls:
                findings.append(self._create_api_finding(component))
            
            if component.has_inline_state_logic:
                findings.append(self._create_logic_finding(component))
        
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
    
    def _create_api_finding(self, component: ReactComponentInfo) -> Finding:
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
        )
    
    def _create_logic_finding(self, component: ReactComponentInfo) -> Finding:
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
