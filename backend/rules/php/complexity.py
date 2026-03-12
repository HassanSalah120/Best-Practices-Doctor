"""
High Complexity Rule
Flags methods with high cyclomatic complexity.
"""
from schemas.facts import Facts, MethodInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class HighComplexityRule(Rule):
    """
    Detects methods with high cyclomatic complexity.
    
    High complexity indicates:
    - Hard to test (many paths)
    - Hard to understand
    - Bug-prone
    """
    
    id = "high-complexity"
    name = "High Complexity Detection"
    description = "Flags methods with high cyclomatic complexity"
    category = Category.COMPLEXITY
    default_severity = Severity.MEDIUM
    
    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings = []
        
        max_cyclomatic = self.get_threshold("max_cyclomatic", 10)
        
        if not metrics:
            return findings
        
        for method_fqn, method_metrics in metrics.items():
            if method_metrics.cyclomatic_complexity > max_cyclomatic:
                # Find the method info
                method = next(
                    (m for m in facts.methods if m.method_fqn == method_fqn),
                    None
                )
                
                if not method:
                    continue
                
                # Skip middleware classes - they often have legitimate high complexity
                if self._is_middleware(method, facts):
                    continue
                
                findings.append(self._create_finding(method, method_metrics, max_cyclomatic))
        
        return findings
    
    def _create_finding(
        self,
        method: MethodInfo,
        metrics: MethodMetrics,
        threshold: int,
    ) -> Finding:
        """Create finding for high complexity method."""
        # Score impact is based on exceedance over threshold (bounded 1..10).
        # This keeps complexity scoring meaningful even in codebases with many complex methods.
        exceed = int(metrics.cyclomatic_complexity) - int(threshold)
        impact = max(1, min(10, exceed))

        finding = self.create_finding(
            title="High cyclomatic complexity",
            context=method.method_fqn,
            file=method.file_path,
            line_start=method.line_start,
            line_end=method.line_end,
            description=(
                f"Method `{method.name}` has cyclomatic complexity of {metrics.cyclomatic_complexity} "
                f"(threshold: {threshold}). This indicates too many decision paths."
            ),
            why_it_matters=(
                f"Cyclomatic complexity measures the number of independent paths through code. "
                f"A complexity of {metrics.cyclomatic_complexity} means you need at least "
                f"{metrics.cyclomatic_complexity} test cases for full coverage. "
                f"High complexity correlates with defect density."
            ),
            suggested_fix=(
                "1. Extract conditional logic into separate methods\n"
                "2. Use early returns to reduce nesting\n"
                "3. Replace nested conditionals with polymorphism\n"
                "4. Consider the Strategy or State pattern for complex branching"
            ),
            code_example=self._generate_example(method.name),
            tags=["complexity", "refactor", "testability"],
        )

        finding.score_impact = impact
        return finding
    
    def _generate_example(self, method_name: str) -> str:
        """Generate refactoring example."""
        return f"""// Before (high complexity)
public function {method_name}($input)
{{
    if ($condition1) {{
        if ($condition2) {{
            // deep nesting
        }} else {{
            // more logic
        }}
    }} elseif ($condition3) {{
        // more branches
    }}
}}

// After (reduced complexity)
public function {method_name}($input)
{{
    if ($this->shouldHandleCase1($input)) {{
        return $this->handleCase1($input);
    }}
    
    if ($this->shouldHandleCase2($input)) {{
        return $this->handleCase2($input);
    }}
    
    return $this->handleDefault($input);
}}"""

    def _is_middleware(self, method: MethodInfo, facts: Facts) -> bool:
        """Check if the method belongs to a middleware class."""
        # Check if the class is a middleware based on file path or class name
        if method.file_path:
            path_lower = method.file_path.lower()
            if "/middleware/" in path_lower or "\\middleware\\" in path_lower:
                return True
        
        # Check if class name contains Middleware
        if method.class_name and "middleware" in method.class_name.lower():
            return True
        
        # Check if the class extends a Middleware base class
        for cls in facts.middleware:
            if cls.name == method.class_name or cls.fqcn == method.class_fqcn:
                return True
        
        return False
