"""
Placeholder as Label Rule

Detects form fields using placeholder as the only label (accessibility issue).
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class PlaceholderAsLabelRule(Rule):
    id = "placeholder-as-label"
    name = "Placeholder Used as Label"
    description = "Detects form fields with placeholder but no associated label"
    category = Category.ACCESSIBILITY
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Input/textarea with placeholder
    _INPUT_WITH_PLACEHOLDER = re.compile(
        r"<(?P<tag>input|textarea)\b(?P<attrs>[^>]*)placeholder=[\"'](?P<placeholder>[^\"']+)[\"'][^>]*>",
        re.IGNORECASE | re.DOTALL,
    )
    
    # Label patterns
    _LABEL_FOR = re.compile(r"<label[^>]*for=[\"'](?P<id>[^\"']+)[\"']", re.IGNORECASE)
    _INPUT_WITH_ID = re.compile(r"\bid=[\"'](?P<id>[^\"']+)[\"']", re.IGNORECASE)
    _ARIA_LABEL = re.compile(r"aria-label(?:ledby)?=[\"'][^\"']+[\"']", re.IGNORECASE)
    _FLOATING_LABEL = re.compile(r"floating|float", re.IGNORECASE)
    
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
        metrics: dict[str, MethodMetrics] | None = None,
        facts: Facts = None,
    ) -> list[Finding]:
        if self._is_allowlisted_path(file_path):
            return []

        findings: list[Finding] = []
        
        # Find all labels and their htmlFor targets
        label_for_ids: set[str] = set()
        for m in self._LABEL_FOR.finditer(content):
            label_for_ids.add(m.group("id").lower())

        # Find inputs with placeholder
        for m in self._INPUT_WITH_PLACEHOLDER.finditer(content):
            attrs = m.group("attrs") or ""
            tag = m.group("tag").lower()
            placeholder = m.group("placeholder") or ""
            
            # Skip hidden, submit, button, reset types
            if re.search(r'type=["\'](?:hidden|submit|button|reset|image)["\']', attrs, re.IGNORECASE):
                continue
            
            # Check if input has ID that matches a label
            id_match = self._INPUT_WITH_ID.search(attrs)
            if id_match:
                input_id = id_match.group("id").lower()
                if input_id in label_for_ids:
                    continue  # Has associated label
            
            # Check for aria-label
            if self._ARIA_LABEL.search(attrs):
                continue  # Has accessible name
            
            # Check for floating label pattern (common UI pattern)
            if self._FLOATING_LABEL.search(content):
                continue  # Likely using floating label UI
            
            # Check if wrapped in label
            # Look backwards for opening <label without closing </label>
            start = m.start()
            before = content[max(0, start - 500):start]
            if re.search(r"<label\b[^>]*>(?![^<]*</label>)", before, re.IGNORECASE | re.DOTALL):
                continue  # Wrapped in label

            line = content.count("\n", 0, m.start()) + 1
            
            findings.append(
                self.create_finding(
                    title="Form field uses placeholder as only label",
                    context=f"{file_path}:{line}:{tag}",
                    file=file_path,
                    line_start=line,
                    description=(
                        f"`<{tag}>` has placeholder \"{placeholder[:30]}...\" but no associated label. "
                        "Placeholder text disappears when users type, and is not a substitute for a proper label."
                    ),
                    why_it_matters=(
                        "Placeholders disappear when the field is filled, leaving users without context.\n"
                        "- Screen readers may not announce placeholders reliably\n"
                        "- Users with cognitive impairments may forget what the field is for\n"
                        "- Low-vision users may miss placeholder text due to low contrast"
                    ),
                    suggested_fix=(
                        "1. Add a visible label with <label htmlFor=\"id\">Label Text</label>\n"
                        "2. Or wrap the input inside a <label>Label Text <input /></label>\n"
                        "3. Or add aria-label=\"Label Text\" for icon-only fields\n"
                        "4. Consider floating label UI pattern for compact forms"
                    ),
                    tags=["ux", "a11y", "forms", "placeholder", "accessibility"],
                    confidence=0.85,
                    evidence_signals=[
                        f"tag={tag}",
                        f"placeholder={placeholder[:30]}",
                        "label_missing=true",
                    ],
                )
            )

        return findings

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)
