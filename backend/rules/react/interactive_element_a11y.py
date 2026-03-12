"""
React Interactive Element A11y Rule

Detects clickable non-semantic elements missing keyboard/role accessibility support.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class InteractiveElementA11yRule(Rule):
    id = "interactive-element-a11y"
    name = "Interactive Element Accessibility"
    description = "Detects non-semantic clickable elements missing role/keyboard handlers"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _TAG_START_PATTERN = re.compile(
        r"<(?P<tag>div|span|li|p|section|article)\b",
        re.IGNORECASE,
    )
    _SELF_CLOSING_PATTERN = re.compile(r"/\s*>")
    _ALLOWLIST_PATH_MARKERS = (
        "/tests/",
        "/test/",
        "/__tests__/",
        "/stories/",
        "/storybook/",
        "/demo/",
        "/demos/",
        "/fixtures/",
        "/generated/",
        "/dist/",
        "/build/",
    )

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        return []

    def _extract_tag_content(self, content: str, start_pos: int) -> tuple[str, int] | None:
        """Extract tag attributes by tracking brace/bracket balance to handle JSX expressions."""
        if start_pos >= len(content):
            return None
        
        # Find the opening <
        if content[start_pos] != '<':
            return None
            
        # Find where the tag name ends (space, newline, or >)
        pos = start_pos + 1
        while pos < len(content) and content[pos].isalnum():
            pos += 1
        
        # Now parse attributes, tracking brace balance
        # { } for JSX expressions, ( ) for function calls, [ ] for arrays
        brace_count = 0
        paren_count = 0
        bracket_count = 0
        in_string = None  # '" or "
        
        while pos < len(content):
            char = content[pos]
            
            # Handle strings
            if in_string:
                if char == in_string and content[pos - 1] != '\\':
                    in_string = None
                pos += 1
                continue
            
            if char in '"\'':
                in_string = char
                pos += 1
                continue
            
            # Track brace balance for JSX expressions
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
            elif char == '(':
                paren_count += 1
            elif char == ')':
                paren_count -= 1
            elif char == '[':
                bracket_count += 1
            elif char == ']':
                bracket_count -= 1
            
            # If we hit > and all braces are balanced, this is the end of the tag
            if char == '>' and brace_count == 0 and paren_count == 0 and bracket_count == 0:
                attrs = content[start_pos + 1:pos]  # Exclude < and >
                # Remove tag name from start
                tag_end = 0
                while tag_end < len(attrs) and (attrs[tag_end].isalnum() or attrs[tag_end] in '._-'):
                    tag_end += 1
                attrs = attrs[tag_end:]
                return attrs, pos
            
            pos += 1
        
        return None  # No closing > found

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
        
        # Find all potential tag starts and extract their content properly
        for m in self._TAG_START_PATTERN.finditer(content):
            start_pos = m.start()
            result = self._extract_tag_content(content, start_pos)
            if not result:
                continue
                
            attrs, end_pos = result
            attrs_lower = attrs.lower()
            
            # Skip if no onClick
            if "onclick" not in attrs_lower:
                continue
                
            # Skip aria-hidden elements
            if "aria-hidden={true}" in attrs_lower or 'aria-hidden="true"' in attrs_lower or "aria-hidden='true'" in attrs_lower:
                continue
                
            # Skip disabled elements
            if "disabled" in attrs_lower:
                continue

            has_role = "role=" in attrs_lower
            has_key_handler = any(k in attrs_lower for k in ["onkeydown", "onkeyup", "onkeypress"])
            has_tabindex = "tabindex=" in attrs_lower
            has_aria_label = "aria-label=" in attrs_lower or "aria-labelledby=" in attrs_lower
            
            # Check if the element already has complete accessibility support
            # Must have ALL of: role, keyboard handler, tabIndex, and accessible label
            if has_role and has_key_handler and has_tabindex and has_aria_label:
                continue
            
            # If it has some accessibility, check for the full set
            if has_role and has_key_handler and has_tabindex:
                # Has core keyboard accessibility but missing label - still more accessible than nothing
                # Check for any aria attribute indicating accessible purpose
                if "aria-" in attrs_lower:
                    continue

            missing: list[str] = []
            if not has_role:
                missing.append("role")
            if not has_key_handler:
                missing.append("keyboard handler")
            if not has_tabindex:
                missing.append("tabIndex")
            if not has_aria_label:
                missing.append("aria-label or aria-labelledby")

            line = content.count("\n", 0, start_pos) + 1
            tag = str(m.group("tag") or "").lower()
            evidence = [
                f"tag={tag}",
                "onclick_present=true",
            ]
            if not has_role:
                evidence.append("role_missing=true")
            if not has_key_handler:
                evidence.append("keyboard_handler_missing=true")
            if not has_tabindex:
                evidence.append("tabindex_missing=true")
            if not has_aria_label:
                evidence.append("aria_label_missing=true")

            findings.append(
                self.create_finding(
                    title="Clickable non-semantic element lacks accessibility support",
                    context=f"{file_path}:{line}:clickable-non-semantic",
                    file=file_path,
                    line_start=line,
                    description=(
                        "Detected non-semantic element with `onClick` but missing accessibility support: "
                        f"{', '.join(missing)}."
                    ),
                    why_it_matters=(
                        "Keyboard and assistive technology users may not be able to operate clickable non-button "
                        "elements unless role and keyboard semantics are added."
                    ),
                    suggested_fix=(
                        "Prefer semantic controls (`<button>`, `<a>`) for interactivity.\n"
                        "If using a non-semantic element, add `role`, keyboard handler, and `tabIndex`."
                    ),
                    tags=["react", "a11y", "accessibility", "keyboard"],
                    confidence=0.88,
                    evidence_signals=evidence,
                )
            )
        return findings

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATH_MARKERS)
