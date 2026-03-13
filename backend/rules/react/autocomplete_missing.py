"""
Autocomplete Missing Rule

Detects form fields without autocomplete attribute for common input types.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class AutocompleteMissingRule(Rule):
    id = "autocomplete-missing"
    name = "Autocomplete Attribute Missing"
    description = "Detects form fields that could benefit from autocomplete attribute"
    category = Category.ACCESSIBILITY
    default_severity = Severity.LOW
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Input types and their suggested autocomplete values
    _AUTOCOMPLETE_MAP = {
        "email": "email",
        "tel": "tel",
        "url": "url",
        "password": "current-password",
        "search": "search",
    }
    
    # Input name/id patterns that suggest autocomplete value
    _NAME_PATTERNS = [
        (re.compile(r'\b(?:name|id)=["\'](?:email|e-mail)["\']', re.IGNORECASE), "email"),
        (re.compile(r'\b(?:name|id)=["\'](?:phone|tel|mobile)["\']', re.IGNORECASE), "tel"),
        (re.compile(r'\b(?:name|id)=["\'](?:password|pass|pwd)["\']', re.IGNORECASE), "current-password"),
        (re.compile(r'\b(?:name|id)=["\'](?:username|user|login)["\']', re.IGNORECASE), "username"),
        (re.compile(r'\b(?:name|id)=["\'](?:first[_-]?name|fname)["\']', re.IGNORECASE), "given-name"),
        (re.compile(r'\b(?:name|id)=["\'](?:last[_-]?name|lname)["\']', re.IGNORECASE), "family-name"),
        (re.compile(r'\b(?:name|id)=["\'](?:address|street)["\']', re.IGNORECASE), "street-address"),
        (re.compile(r'\b(?:name|id)=["\'](?:city)["\']', re.IGNORECASE), "address-level2"),
        (re.compile(r'\b(?:name|id)=["\'](?:state|province|region)["\']', re.IGNORECASE), "address-level1"),
        (re.compile(r'\b(?:name|id)=["\'](?:zip|postal)["\']', re.IGNORECASE), "postal-code"),
        (re.compile(r'\b(?:name|id)=["\'](?:country)["\']', re.IGNORECASE), "country"),
        (re.compile(r'\b(?:name|id)=["\'](?:credit[_-]?card|cc[_-]?number)["\']', re.IGNORECASE), "cc-number"),
    ]
    
    _INPUT_PATTERN = re.compile(
        r"<input\b(?P<attrs>[^>]*)>",
        re.IGNORECASE | re.DOTALL,
    )
    
    _TEXTAREA_PATTERN = re.compile(
        r"<textarea\b(?P<attrs>[^>]*)>",
        re.IGNORECASE | re.DOTALL,
    )
    
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

        # Check inputs
        for m in self._INPUT_PATTERN.finditer(content):
            line = content.count("\n", 0, m.start()) + 1
            if line in seen_lines:
                continue
            
            attrs = m.group("attrs") or ""
            
            # Skip hidden, submit, button, reset, file, image types
            if re.search(r'type=["\'](?:hidden|submit|button|reset|file|image|checkbox|radio)["\']', attrs, re.IGNORECASE):
                continue
            
            # Check if already has autocomplete attribute
            if re.search(r'\bautocomplete=["\'][^"\']+["\']', attrs, re.IGNORECASE):
                continue
            
            # Skip if uses {...field} spread (react-hook-form) - autocomplete may be in spread
            if re.search(r'\{\s*\.\.\.\s*field\s*\}', attrs, re.IGNORECASE):
                continue
            
            # Skip custom Input components that handle autocomplete internally
            line_content = content.split("\n")[line - 1] if line > 0 else ""
            if re.search(r'<Input\b', line_content, re.IGNORECASE):
                continue
            
            # Determine suggested autocomplete value
            suggested = self._get_suggested_autocomplete(attrs)
            if not suggested:
                continue
            
            seen_lines.add(line)
            findings.append(
                self.create_finding(
                    title="Form field missing autocomplete attribute",
                    context=f"{file_path}:{line}:input-autocomplete",
                    file=file_path,
                    line_start=line,
                    description=(
                        f"Input field could benefit from `autocomplete=\"{suggested}\"` attribute. "
                        "This helps browsers autofill the field, improving user experience."
                    ),
                    why_it_matters=(
                        "Autocomplete attributes:\n"
                        "- Help users fill forms faster (especially on mobile)\n"
                        "- Reduce typing errors for email, address, etc.\n"
                        "- Improve accessibility for users with motor impairments\n"
                        "- Are recommended by WCAG 1.3.5 (Identify Input Purpose)"
                    ),
                    suggested_fix=f'Add `autocomplete="{suggested}"` to the input element.',
                    tags=["ux", "a11y", "forms", "autocomplete", "accessibility"],
                    confidence=0.70,
                    evidence_signals=[
                        f"suggested_autocomplete={suggested}",
                    ],
                )
            )

        return findings

    def _get_suggested_autocomplete(self, attrs: str) -> str | None:
        """Determine suggested autocomplete value from input attributes."""
        # Check type attribute
        type_match = re.search(r'type=["\'](\w+)["\']', attrs, re.IGNORECASE)
        if type_match:
            input_type = type_match.group(1).lower()
            if input_type in self._AUTOCOMPLETE_MAP:
                return self._AUTOCOMPLETE_MAP[input_type]
        
        # Check name/id patterns
        for pattern, value in self._NAME_PATTERNS:
            if pattern.search(attrs):
                return value
        
        return None

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)
