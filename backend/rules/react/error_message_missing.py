"""
Error Message Missing Rule

Detects form fields with validation but no associated error message pattern.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class ErrorMessageMissingRule(Rule):
    id = "error-message-missing"
    name = "Error Message Missing"
    description = "Detects form fields with validation but no error message association"
    category = Category.ACCESSIBILITY
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Input patterns with validation indicators
    _INPUT_PATTERN = re.compile(
        r"<(?P<tag>input|select|textarea)\b(?P<attrs>[^>]*)>",
        re.IGNORECASE | re.DOTALL,
    )
    
    # Validation indicators
    _VALIDATION_PATTERNS = [
        re.compile(r'required', re.IGNORECASE),
        re.compile(r'pattern=', re.IGNORECASE),
        re.compile(r'min=', re.IGNORECASE),
        re.compile(r'max=', re.IGNORECASE),
        re.compile(r'minlength=', re.IGNORECASE),
        re.compile(r'maxlength=', re.IGNORECASE),
        re.compile(r'type=["\'](?:email|url|tel|number)["\']', re.IGNORECASE),
    ]
    
    # Error message patterns (good)
    _ERROR_PATTERNS = [
        re.compile(r'aria-errormessage=["\'][^"\']+["\']', re.IGNORECASE),
        re.compile(r'aria-describedby=["\'][^"\']+["\']', re.IGNORECASE),
        re.compile(r'role=["\']alert["\']', re.IGNORECASE),  # Live region for errors
        re.compile(r'error', re.IGNORECASE),
        re.compile(r'invalid', re.IGNORECASE),
        re.compile(r'errorMessage', re.IGNORECASE),
        re.compile(r'errorText', re.IGNORECASE),
    ]
    
    _ALLOWLIST_PATHS = (
        "/tests/",
        "/test/",
        "/__tests__/",
        "/stories/",
        "/storybook/",
    )

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._is_allowlisted_path(file_path):
            return []

        findings: list[Finding] = []
        seen_lines: set[int] = set()
        
        # Check if file has any error handling patterns
        file_has_error_handling = any(p.search(content) for p in self._ERROR_PATTERNS)

        for m in self._INPUT_PATTERN.finditer(content):
            line = content.count("\n", 0, m.start()) + 1
            if line in seen_lines:
                continue
            
            tag = m.group("tag").lower()
            attrs = m.group("attrs") or ""
            
            # Skip hidden/disabled
            if self._is_hidden_or_disabled(attrs):
                continue
            
            # Check if field has validation
            has_validation = any(p.search(attrs) for p in self._VALIDATION_PATTERNS)
            if not has_validation:
                continue
            
            # Check if field has error message association
            has_error_association = any(p.search(attrs) for p in self._ERROR_PATTERNS[:2])  # aria-errormessage, aria-describedby
            
            if has_error_association:
                continue
            
            # Check if there's error handling nearby in the file
            if file_has_error_handling:
                continue  # Likely handled elsewhere
            
            seen_lines.add(line)
            findings.append(
                self.create_finding(
                    title="Form field lacks error message association",
                    context=f"{file_path}:{line}:{tag}",
                    file=file_path,
                    line_start=line,
                    description=(
                        f"`<{tag}>` has validation (required, pattern, etc.) but no `aria-errormessage` "
                        "or `aria-describedby` to associate error messages."
                    ),
                    why_it_matters=(
                        "WCAG 3.3.1 requires error identification.\n"
                        "- Screen reader users need to know when a field has an error\n"
                        "- Users need to understand what the error is\n"
                        "- Without association, errors may be announced out of context"
                    ),
                    suggested_fix=(
                        "1. Add aria-errormessage pointing to error element:\n"
                        '   <input required aria-errormessage="email-error" />\n'
                        '   <span id="email-error" role="alert">Please enter a valid email</span>\n'
                        "2. Or use aria-describedby for help text:\n"
                        '   <input aria-describedby="email-hint" />'
                    ),
                    tags=["ux", "a11y", "forms", "validation", "accessibility"],
                    confidence=0.65,
                    evidence_signals=[
                        f"tag={tag}",
                        "validation_present=true",
                        "error_message_association_missing=true",
                    ],
                )
            )

        return findings

    def _is_hidden_or_disabled(self, attrs: str) -> bool:
        attrs_lower = attrs.lower()
        return (
            "hidden" in attrs_lower
            or "disabled" in attrs_lower
            or 'type="hidden"' in attrs_lower
        )

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)
