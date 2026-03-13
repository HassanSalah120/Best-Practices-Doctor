"""
Custom Exception Suggestion Rule

Suggests creating domain-specific exceptions instead of generic Exceptions.
"""
from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class CustomExceptionSuggestionRule(Rule):
    """
    Suggests using custom exceptions.
    
    Triggers when:
    - Code throws generic `\\Exception` or `Exception`
    - Code catches generic `\\Exception` or `Exception` (maybe separately)
    - Exception message is hardcoded string
    """
    
    id = "custom-exception-suggestion"
    name = "Custom Exception Usage"
    description = "Suggests using specific exceptions instead of generic ones"
    category = Category.ARCHITECTURE
    default_severity = Severity.HIGH
    applicable_project_types = ["laravel_api", "laravel_blade", "laravel_inertia_react", "laravel_inertia_vue"]
    _GENERIC_EXCEPTIONS = {"Exception", "RuntimeException", "LogicException", "Throwable"}
    _ALLOWLIST_PATH_MARKERS = (
        "/tests/",
        "/test/",
        "/console/",
        "/commands/",
        "/providers/",
        "/middleware/",
        "/vendor/",
    )
    _ALLOWLIST_METHODS = {"report", "render", "register", "boot"}
    _DOMAIN_PATH_MARKERS = (
        "/services/",
        "/actions/",
        "/domain/",
        "/repositories/",
        "/http/controllers/",
    )
    
    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        has_custom_exceptions = self._project_has_custom_exceptions(facts)
        shared_infra_roots = tuple(
            str(root or "").lower().replace("\\", "/")
            for root in (getattr(getattr(facts, "project_context", None), "shared_infra_roots", []) or [])
        )
        
        for method in facts.methods:
            if self._is_allowlisted_method(method, shared_infra_roots):
                continue

            for exception_class in method.throws:
                exc = (exception_class or "").lstrip("\\")
                if exc not in self._GENERIC_EXCEPTIONS:
                    continue

                confidence = self._confidence_for_method(method, has_custom_exceptions)
                severity = self.severity if confidence >= 0.7 else Severity.LOW
                findings.append(self.create_finding(
                        title="Avoid throwing generic exception",
                        context=method.method_fqn,
                        file=method.file_path,
                        line_start=method.line_start,
                        line_end=method.line_end,
                        description=(
                            f"Method `{method.name}` throws a generic `{exc}`. "
                            f"This makes error handling difficult as callers cannot catch specific failure types."
                        ),
                        why_it_matters=(
                            "Using custom exceptions (e.g., `PaymentFailedException`) allows for "
                            "granular error handling, better logging, and self-documenting code."
                        ),
                        suggested_fix="Create a domain-specific exception class and throw that instead.",
                        code_example=self._generate_throw_example(method.name),
                        severity=severity,
                        confidence=confidence,
                        tags=["architecture", "error-handling"],
                    ))

        return findings

    def _project_has_custom_exceptions(self, facts: Facts) -> bool:
        for exc in facts.exceptions:
            low = str(getattr(exc, "file_path", "") or "").lower().replace("\\", "/")
            if any(marker in low for marker in self._ALLOWLIST_PATH_MARKERS):
                continue
            return True
        return False

    def _is_allowlisted_method(self, method, shared_infra_roots: tuple[str, ...] = ()) -> bool:
        low_path = str(getattr(method, "file_path", "") or "").lower().replace("\\", "/")
        if any(marker in low_path for marker in self._ALLOWLIST_PATH_MARKERS):
            return True
        if any(low_path.startswith(root.rstrip("/") + "/") for root in shared_infra_roots if root.startswith("app/")):
            return True
        low_name = str(getattr(method, "name", "") or "").lower()
        return low_name in self._ALLOWLIST_METHODS

    def _confidence_for_method(self, method, has_custom_exceptions: bool) -> float:
        low_path = str(getattr(method, "file_path", "") or "").lower().replace("\\", "/")
        confidence = 0.56
        if any(marker in low_path for marker in self._DOMAIN_PATH_MARKERS):
            confidence += 0.12
        if has_custom_exceptions:
            confidence += 0.16
        if int(getattr(method, "loc", 0) or 0) >= 12:
            confidence += 0.05
        if len(getattr(method, "call_sites", []) or []) >= 2:
            confidence += 0.05
        return min(0.92, confidence)
    
    def _generate_throw_example(self, method_name: str) -> str:
        return f"""// Before: Generic Exception
throw new Exception("User not found");

// After: Domain Exception
throw new UserNotFoundException("User not found");

// app/Exceptions/UserNotFoundException.php
class UserNotFoundException extends Exception {{}}"""
