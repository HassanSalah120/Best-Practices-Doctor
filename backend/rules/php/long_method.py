"""
Long Method Rule
Flags methods that exceed reasonable length.
"""
from schemas.facts import Facts, MethodInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class LongMethodRule(Rule):
    """
    Detects methods that are too long.
    
    Long methods typically:
    - Do too many things (SRP violation)
    - Are hard to understand
    - Are hard to test
    """
    
    id = "long-method"
    name = "Long Method Detection"
    description = "Flags methods exceeding recommended length"
    category = Category.SRP
    default_severity = Severity.LOW
    
    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings = []
        
        # Backwards/forwards compatible threshold keys.
        max_lines = self.get_threshold("max_lines", self.get_threshold("max_loc", 30))
        
        for method in facts.methods:
            if method.loc > max_lines:
                findings.append(self._create_finding(method, max_lines))
        
        return findings
    
    def _create_finding(self, method: MethodInfo, threshold: int) -> Finding:
        """Create finding for long method."""
        # Score impact is proportional to how far over the threshold the method is (bounded 1..10).
        exceed = int(method.loc) - int(threshold)
        impact = max(1, min(10, (exceed + 9) // 10))

        finding = self.create_finding(
            title=f"Methods should be short and focused",
            context=method.method_fqn,
            file=method.file_path,
            line_start=method.line_start,
            line_end=method.line_end,
            description=(
                f"Method `{method.name}` has {method.loc} lines "
                f"(recommended max: {threshold}). Consider breaking it down."
            ),
            why_it_matters=(
                "Long methods are harder to read, test, and maintain. "
                "They typically do too many things, violating the Single Responsibility Principle. "
                "Shorter methods are more reusable and easier to name descriptively."
            ),
            suggested_fix=(
                "1. Identify logical sections within the method\n"
                "2. Extract each section into a well-named private method\n"
                "3. The main method should read like a high-level summary\n"
                "4. Each extracted method should do one thing"
            ),
            code_example=self._generate_example(method.name),
            tags=["srp", "refactor", "readability"],
        )

        finding.score_impact = int(impact)
        return finding
    
    def _generate_example(self, method_name: str) -> str:
        """Generate refactoring example."""
        return f"""// Before (50+ lines)
public function {method_name}()
{{
    // validate input (10 lines)
    // fetch data (15 lines)
    // process data (20 lines)
    // save results (10 lines)
}}

// After (clear structure)
public function {method_name}()
{{
    $input = $this->validateInput();
    $data = $this->fetchData($input);
    $result = $this->processData($data);
    return $this->saveResults($result);
}}"""
