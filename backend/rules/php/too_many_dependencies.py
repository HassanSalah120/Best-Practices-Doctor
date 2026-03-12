"""
Too Many Dependencies Rule

Flags constructors with too many injected dependencies (tight coupling / SRP smell).
"""
from schemas.facts import Facts, MethodInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class TooManyDependenciesRule(Rule):
    """
    Detects constructors with too many parameters (dependencies).
    """

    id = "too-many-dependencies"
    name = "Too Many Constructor Dependencies"
    description = "Detects constructors with too many dependencies (likely SRP violation)"
    category = Category.MAINTAINABILITY
    default_severity = Severity.MEDIUM
    applicable_project_types: list[str] = []  # all

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        max_deps = int(self.get_threshold("max_dependencies", 5))

        for m in facts.methods:
            if m.name != "__construct":
                continue
            
            # Skip DTOs - they have data properties, not service dependencies
            if self._is_dto(m, facts):
                continue
            
            # Skip orchestrators/coordinators - they intentionally coordinate multiple services
            if self._is_orchestrator(m, facts):
                continue
            
            dep_count = len(m.parameters or [])
            if dep_count <= max_deps:
                continue

            ctx = m.method_fqn
            findings.append(
                self.create_finding(
                    title="Constructor has too many dependencies",
                    context=ctx,
                    file=m.file_path,
                    line_start=m.line_start,
                    line_end=m.line_end,
                    description=(
                        f"Constructor `{m.method_fqn}` has {dep_count} parameters (threshold: {max_deps}). "
                        "This often indicates a class doing too much or a missing abstraction."
                    ),
                    why_it_matters=(
                        "Classes with many dependencies are hard to test, hard to reuse, and tend to violate SRP. "
                        "They also make DI graphs brittle and increase the cost of change."
                    ),
                    suggested_fix=(
                        "1. Split responsibilities into smaller services\n"
                        "2. Introduce a Facade/Coordinator that composes smaller collaborators\n"
                        "3. Group related dependencies behind an interface\n"
                        "4. Consider an Action class per use-case"
                    ),
                    tags=["maintainability", "srp", "coupling", "di"],
                )
            )

        return findings
    
    def _is_dto(self, method: MethodInfo, facts: Facts) -> bool:
        """Check if the class is a DTO (Data Transfer Object) - these have data properties, not service dependencies."""
        # Check file path for DTO markers
        if method.file_path:
            path_lower = method.file_path.lower().replace("\\", "/")
            if "/dto/" in path_lower or "/dtos/" in path_lower:
                return True
            # Check filename
            filename = path_lower.split("/")[-1] if "/" in path_lower else path_lower
            if "dto" in filename.lower():
                return True
        
        # Check if class name ends with DTO
        if method.class_name and method.class_name.lower().endswith("dto"):
            return True
        
        return False

    def _is_orchestrator(self, method: MethodInfo, facts: Facts) -> bool:
        """Check if the class is an orchestrator/coordinator - these intentionally have many dependencies."""
        class_name = (method.class_name or "").lower()
        
        # Check class name patterns for orchestrator/coordinator
        orchestrator_patterns = [
            "coordinator",
            "orchestrator",
            "workflow",
            "processmanager",
            "saga",
        ]
        if any(pattern in class_name for pattern in orchestrator_patterns):
            return True
        
        # Check for service classes that orchestrate multi-step workflows
        # These typically have names like InsuranceClaimService, OrderProcessingService
        workflow_service_patterns = [
            "claimservice",
            "orderservice",
            "processingservice",
            "workflowservice",
            "financialservice",
        ]
        if any(pattern in class_name for pattern in workflow_service_patterns):
            return True
        
        # Check file path for coordination/workflow folders
        if method.file_path:
            path_lower = method.file_path.lower().replace("\\", "/")
            if "/coordination/" in path_lower or "/workflows/" in path_lower or "/workflow/" in path_lower:
                return True
        
        return False

