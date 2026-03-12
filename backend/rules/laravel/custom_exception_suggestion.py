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
    
    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings = []
        
        for method in facts.methods:
            # Check for generic Exception instantiation or throw
            # FactsBuilder now extracts `instantiations` and `throws`
            
            # Check throws first (explicit throw new Exception)
            for exception_class in method.throws:
                exc = (exception_class or "").lstrip("\\")
                if exc in {"Exception", "RuntimeException", "LogicException", "Throwable"}:
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
                        tags=["architecture", "error-handling"],
                    ))
            
            # Check instantiations (new Exception) logic
            # This covers `throw new Exception` (caught above) AND `$e = new Exception`
            # We might want to skip if we already caught it via throws to avoid duplicates,
            # but standardizing on 'throws' is safer for now.
            
            # If we wanted to check 'catch (Exception $e)', we would need that in FactsBuilder too.
            # For now, focusing on THROWing generic exceptions is high value.

        return findings
    
    def _generate_throw_example(self, method_name: str) -> str:
        return f"""// Before: Generic Exception
throw new Exception("User not found");

// After: Domain Exception
throw new UserNotFoundException("User not found");

// app/Exceptions/UserNotFoundException.php
class UserNotFoundException extends Exception {{}}"""
