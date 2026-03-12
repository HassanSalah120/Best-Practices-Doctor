"""
Contract Suggestion Rule

Suggests injecting interfaces (contracts) instead of concrete classes.
"""
from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class ContractSuggestionRule(Rule):
    """
    Suggests using interfaces for dependency injection.
    
    Triggers when:
    - Concrete classes are type-hinted in constructors
    - Especially for Service or Repository classes
    """
    
    id = "contract-suggestion"
    name = "Contract-Based Development"
    description = "Suggests using Interfaces (Contracts) for dependency injection"
    category = Category.ARCHITECTURE
    default_severity = Severity.LOW
    applicable_project_types = ["laravel_api", "laravel_blade", "laravel_inertia_react", "laravel_inertia_vue"]
    
    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings = []
        
        # Analyze constructors
        for method in facts.methods:
            if method.name != "__construct":
                continue
                
            # Check constructor parameters for concrete type hints
            for param in method.parameters:
                parsed = self._parse_typed_param(param)
                if not parsed:
                    continue

                type_hint, var_name = parsed
                base = type_hint.split("\\")[-1]

                if not (base.endswith("Service") or base.endswith("Repository")):
                    continue
                if base.endswith("Interface") or base.endswith("Contract"):
                    continue

                findings.append(self.create_finding(
                    title=f"Type-hint Interface instead of Concrete Class: {base}",
                    file=method.file_path,
                    line_start=method.line_start,
                    line_end=method.line_end,
                    description=(
                        f"Constructor parameter `{var_name}` is type-hinted with concrete class `{type_hint}`. "
                        "Depend on abstractions (Interfaces/Contracts) instead of concretions."
                    ),
                    why_it_matters=(
                        "Dependency Inversion Principle (SOLID). "
                        "Using interfaces allows for easier testing (mocking) and swapping implementations."
                    ),
                    suggested_fix=f"Create `{base}Interface` and type-hint that instead.",
                    code_example=self._generate_example(base, var_name),
                    tags=["architecture", "solid", "dependency-injection"],
                ))

        return findings

    def _parse_typed_param(self, raw: str) -> tuple[str, str] | None:
        """Parse `Type $var` from a constructor param string."""
        import re

        # Handles:
        # - "UserService $userService"
        # - "App\\Services\\UserService $svc"
        # - "private UserService $svc" (property promotion)
        # - "private readonly App\\Services\\UserService $svc"
        # - "?UserService $svc"
        # - "UserService|Foo $svc" (picks first non-null type)
        m = re.match(
            r"^\s*(?:(?:public|protected|private)\s+)?(?:readonly\s+)?(?P<type>[^\s]+)\s+(?P<var>\$\w+)\s*$",
            raw,
        )
        if not m:
            return None

        t = m.group("type").strip()
        v = m.group("var").strip()

        # Normalize union/nullable
        t = t.lstrip("?")
        if "|" in t:
            parts = [p for p in t.split("|") if p and p.lower() != "null"]
            if parts:
                t = parts[0].lstrip("?")

        return (t, v)

    def _generate_example(self, class_name: str, var_name: str) -> str:
        interface_name = f"{class_name}Interface"
        return f"""// Before: High Coupling
 public function __construct({class_name} {var_name})
{{
     $this->service = {var_name};
}}

// After: Low Coupling (Dependency Inversion)
public function __construct({interface_name} {var_name})
{{
    $this->service = {var_name};
}}
"""
