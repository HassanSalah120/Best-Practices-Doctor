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
        classes_by_fqcn = {str(c.fqcn or "").lstrip("\\"): c for c in facts.classes if c.fqcn}
        fqcn_by_basename = self._build_fqcn_by_basename(classes_by_fqcn)
        known_contracts = {
            str(c.fqcn or "").split("\\")[-1]
            for c in [*facts.contracts, *facts.classes]
            if str(c.fqcn or "").split("\\")[-1].endswith(("Interface", "Contract"))
        }
        
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
                if self._has_existing_contract(type_hint, classes_by_fqcn, fqcn_by_basename, known_contracts):
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

    @staticmethod
    def _build_fqcn_by_basename(classes_by_fqcn: dict[str, object]) -> dict[str, str]:
        out: dict[str, str] = {}
        ambiguous: set[str] = set()
        for fqcn in classes_by_fqcn.keys():
            base = fqcn.split("\\")[-1]
            if base in ambiguous:
                continue
            if base in out:
                out.pop(base, None)
                ambiguous.add(base)
                continue
            out[base] = fqcn
        return out

    def _has_existing_contract(
        self,
        type_hint: str,
        classes_by_fqcn: dict[str, object],
        fqcn_by_basename: dict[str, str],
        known_contracts: set[str],
    ) -> bool:
        normalized = str(type_hint or "").lstrip("\\")
        base = normalized.split("\\")[-1]
        resolved = classes_by_fqcn.get(normalized) or classes_by_fqcn.get(fqcn_by_basename.get(base, ""))
        if resolved and getattr(resolved, "implements", None):
            return True

        candidate_names = {
            f"{base}Interface",
            f"{base}Contract",
        }
        if base.endswith("Service"):
            root = base[: -len("Service")]
            candidate_names.update({f"{root}ServiceInterface", f"{root}ServiceContract"})
        if base.endswith("Repository"):
            root = base[: -len("Repository")]
            candidate_names.update({f"{root}RepositoryInterface", f"{root}RepositoryContract"})

        return any(name in known_contracts for name in candidate_names)

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
