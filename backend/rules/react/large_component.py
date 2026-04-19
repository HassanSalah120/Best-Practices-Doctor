"""
Large React Component Rule
Detects React components that are too large.
"""
from core.path_utils import normalize_rel_path
from schemas.facts import Facts, ReactComponentInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class LargeComponentRule(Rule):
    """
    Detects React components that exceed reasonable size.
    
    Large components typically:
    - Have too many responsibilities
    - Are hard to test
    - Should be split into smaller components
    """
    
    id = "large-react-component"
    name = "Large React Component Detection"
    description = "Detects oversized React components"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    # Run whenever React components were detected (facts.react_components),
    # regardless of detected project type (some repos don't have package.json at root).
    applicable_project_types: list[str] = []
    _PAGE_PATH_MARKERS = ("/pages/", "/page/", "/screens/", "/screen/", "/views/", "/view/", "/routes/", "/route/")
    _LOCAL_UI_IMPORT_MARKERS = (
        "/components/",
        "/component/",
        "/widgets/",
        "/widget/",
        "/modals/",
        "/panels/",
        "/sections/",
        "./",
        "../",
        "@/components",
        "@/widgets",
        "@/pages",
        "@/screens",
        "@/views",
        "@/features",
    )
    _SHELL_NAME_MARKERS = ("dashboard", "portal", "panel", "modal", "board", "workspace", "shell", "layout", "screen", "view")
    
    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings = []
        
        # Backwards/forwards compatible threshold keys.
        max_lines = self.get_threshold("max_lines", self.get_threshold("max_loc", 200))
        min_loc_to_consider = max(120, int(self.get_threshold("min_loc_to_consider", 240)))
        min_overflow_lines = max(0, int(self.get_threshold("min_overflow_lines", 20)))
        
        for component in facts.react_components:
            if component.loc < min_loc_to_consider:
                continue
            profile = self._component_profile(component, max_lines, facts)
            threshold = int(profile["threshold"])
            if component.loc >= (threshold + min_overflow_lines):
                findings.append(self._create_finding(component, threshold, profile))
        
        return findings

    def _component_profile(self, component: ReactComponentInfo, base_threshold: int, facts: Facts) -> dict[str, object]:
        path = str(component.file_path or "").replace("\\", "/").lower()
        name = str(component.name or "")
        name_low = name.lower()
        is_page = any(marker in path for marker in self._PAGE_PATH_MARKERS) or ("/features/" in path and any(marker in path for marker in ("/pages/", "/views/", "/screens/"))) or name.endswith(("Page", "Screen", "View"))

        imports = [str(imp or "").lower() for imp in self._component_imports(component, facts)]
        has_custom_hook_import = any("/hooks/" in imp or "\\hooks\\" in imp or "/use" in imp for imp in imports)
        local_component_imports = sum(
            1
            for imp in imports
            if any(marker in imp for marker in self._LOCAL_UI_IMPORT_MARKERS)
        )
        is_static_marketing_page = any(token in name_low for token in ("welcome", "landing", "home"))
        is_feature_shell = local_component_imports >= 3 or (has_custom_hook_import and local_component_imports >= 2)
        is_composed_shell = has_custom_hook_import and local_component_imports >= 2
        is_complex_ui_shell = is_feature_shell or any(token in name_low for token in self._SHELL_NAME_MARKERS)
        project_type = str(getattr(getattr(facts, "project_context", None), "project_type", "unknown") or "unknown")
        react_mode = str(
            getattr(getattr(facts, "project_context", None), "react_structure_mode", "unknown") or "unknown"
        ).lower()
        capabilities = getattr(getattr(facts, "project_context", None), "capabilities", {}) or {}
        has_realtime = bool((capabilities.get("realtime") or {}).get("enabled", False))
        has_mixed_dashboard = bool((capabilities.get("mixed_public_dashboard") or {}).get("enabled", False))

        shell_threshold = int(self.get_threshold("max_lines_component_shell", 420))
        feature_threshold = int(self.get_threshold("max_lines_feature_shell", 520))
        composed_threshold = int(self.get_threshold("max_lines_composed_shell", 700))
        static_threshold = int(self.get_threshold("max_lines_static_page", 420))

        threshold = base_threshold
        if not is_page:
            if is_feature_shell or (is_complex_ui_shell and (is_composed_shell or local_component_imports >= 2)):
                threshold = max(base_threshold, shell_threshold)
            else:
                threshold = base_threshold
        elif is_composed_shell and is_complex_ui_shell:
            threshold = max(base_threshold, composed_threshold)
        elif is_feature_shell:
            threshold = max(base_threshold, feature_threshold)
        elif has_custom_hook_import or is_static_marketing_page:
            threshold = max(base_threshold, static_threshold)
        else:
            threshold = max(base_threshold, 300)

        if project_type == "realtime_game_control_platform" or has_realtime:
            threshold += 100
        elif project_type in {"portal_based_business_app", "public_website_with_dashboard"} or has_mixed_dashboard:
            threshold += 60

        if react_mode == "hybrid":
            threshold += 40

        return {
            "threshold": threshold,
            "is_page": is_page,
            "has_custom_hook_import": has_custom_hook_import,
            "local_component_imports": local_component_imports,
            "is_static_marketing_page": is_static_marketing_page,
            "is_composed_shell": is_composed_shell,
            "is_feature_shell": is_feature_shell,
            "is_complex_ui_shell": is_complex_ui_shell,
            "project_type": project_type,
            "react_structure_mode": react_mode,
            "evidence_signals": [
                f"is_page={int(is_page)}",
                f"hooks={int(has_custom_hook_import)}",
                f"local_components={local_component_imports}",
                f"feature_shell={int(is_feature_shell)}",
                f"complex_shell={int(is_complex_ui_shell)}",
                f"project_type={project_type}",
                f"react_structure={react_mode}",
                f"threshold={threshold}",
            ],
        }

    @staticmethod
    def _component_imports(component: ReactComponentInfo, facts: Facts) -> list[str]:
        imports = [str(imp or "") for imp in (component.imports or []) if str(imp or "").strip()]
        if imports:
            return imports

        graph = getattr(facts, "_frontend_symbol_graph", None)
        files_map = graph.get("files", {}) if isinstance(graph, dict) else {}
        payload = files_map.get(normalize_rel_path(str(component.file_path or "")))
        if not isinstance(payload, dict):
            return []
        return [str(imp or "") for imp in (payload.get("imports", []) or []) if str(imp or "").strip()]
    
    def _create_finding(self, component: ReactComponentInfo, threshold: int, profile: dict[str, object]) -> Finding:
        """Create finding for large component."""
        return self.create_finding(
            title="React component is too large",
            context=component.name,
            file=component.file_path,
            line_start=component.line_start,
            line_end=component.line_end,
            description=(
                f"Component `{component.name}` has {component.loc} lines "
                f"(recommended max: {threshold}). Consider splitting it."
            ),
            why_it_matters=(
                "Large components are harder to understand, test, and maintain. "
                "They often mix presentation and logic, making reuse difficult. "
                "Smaller components are easier to reason about and compose."
            ),
            suggested_fix=(
                "1. Identify distinct UI sections that could be separate components\n"
                "2. Extract logic into custom hooks\n"
                "3. Use composition to combine smaller components\n"
                "4. Consider container/presenter pattern"
            ),
            code_example=self._generate_example(component.name),
            tags=["react", "refactor", "component-design"],
            evidence_signals=profile["evidence_signals"],
            metadata={"decision_profile": profile},
        )
    
    def _generate_example(self, name: str) -> str:
        """Generate refactoring example."""
        return f"""// Before (300+ lines in {name})
export function {name}() {{
    // 50 lines of state and effects
    // 100 lines of handlers
    // 150 lines of JSX
}}

// After (split into smaller components)
export function {name}() {{
    const {{ data, handlers }} = use{name}Logic();
    
    return (
        <{name}Layout>
            <{name}Header data={{data}} />
            <{name}Content data={{data}} handlers={{handlers}} />
            <{name}Footer />
        </{name}Layout>
    );
}}"""
