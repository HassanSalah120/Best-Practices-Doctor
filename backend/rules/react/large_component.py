"""
Large React Component Rule
Detects React components that are too large.
"""
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
    
    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings = []
        
        # Backwards/forwards compatible threshold keys.
        max_lines = self.get_threshold("max_lines", self.get_threshold("max_loc", 200))
        
        for component in facts.react_components:
            if component.loc > max_lines:
                findings.append(self._create_finding(component, max_lines))
        
        return findings
    
    def _create_finding(self, component: ReactComponentInfo, threshold: int) -> Finding:
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
