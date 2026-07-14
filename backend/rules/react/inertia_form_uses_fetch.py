"""
Inertia Form Uses Fetch Rule

Detects Inertia page forms that submit with fetch/axios instead of `useForm`.
"""

from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class InertiaFormUsesFetchRule(Rule):
    id = "inertia-form-uses-fetch"
    name = "Inertia Form Uses Fetch"
    description = "Detects Inertia page forms using fetch/axios instead of useForm"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types = ["laravel_inertia_react"]
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Refactor the component code to remove the inertia form uses fetch pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 3
    group = 'Code Quality'
    applies_to = ['react-component', 'form']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'inertia-form-uses'}

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
        text = content or ""
        if "<form" not in text:
            return []
        if "useForm(" in text:
            return []
        submission = self._form_submission_source(text)
        if not submission or ("fetch(" not in submission and "axios." not in submission):
            return []

        return [
            self.create_finding(
                title="Inertia page form uses fetch/axios instead of useForm",
                context=f"file:{file_path}",
                file=file_path,
                line_start=1,
                description=(
                    "Detected a form inside an Inertia page that submits via `fetch`/`axios` without"
                    " using Inertia's `useForm` helper."
                ),
                why_it_matters=(
                    "`useForm` gives Inertia-native validation/error handling, progress state,"
                    " and visit behavior. Raw fetch/axios usually duplicates that logic."
                ),
                suggested_fix=(
                    "Prefer `useForm` from `@inertiajs/react` for standard page forms, and only use"
                    " raw HTTP clients when the flow is intentionally outside the Inertia visit model."
                ),
                tags=["react", "inertia", "forms", "useform"],
                confidence=0.83,
                evidence_signals=[f"file={file_path}", "raw_http_form_submission=true"],
            ),
        ]

    def _form_submission_source(self, text: str) -> str:
        """Return only the handler wired to a form submission."""
        for attrs in self._opening_form_attributes(text):
            prop = re.search(r"\bonSubmit\s*=\s*\{", attrs, re.IGNORECASE)
            if not prop:
                continue
            open_brace = attrs.find("{", prop.start())
            payload = self._balanced_braced_expression(attrs, open_brace)
            if payload is None:
                continue
            if "fetch(" in payload or "axios." in payload:
                return payload
            handler = re.fullmatch(r"\s*([A-Za-z_$][\w$]*)\s*", payload)
            if not handler:
                continue
            body = self._named_handler_body(text, handler.group(1))
            if body:
                return body
        return ""

    def _opening_form_attributes(self, text: str) -> list[str]:
        """Extract form tags without treating an arrow's `>` as the tag end."""
        tags: list[str] = []
        for match in re.finditer(r"<form\b", text, re.IGNORECASE):
            start = match.end()
            brace_depth = 0
            quote = ""
            escaped = False
            for index in range(start, len(text)):
                char = text[index]
                if quote:
                    if escaped:
                        escaped = False
                    elif char == "\\":
                        escaped = True
                    elif char == quote:
                        quote = ""
                    continue
                if char in {"'", '"', "`"}:
                    quote = char
                elif char == "{":
                    brace_depth += 1
                elif char == "}":
                    brace_depth = max(0, brace_depth - 1)
                elif char == ">" and brace_depth == 0:
                    tags.append(text[start:index])
                    break
        return tags

    def _balanced_braced_expression(self, text: str, open_brace: int) -> str | None:
        if open_brace < 0:
            return None
        depth = 0
        quote = ""
        escaped = False
        for index in range(open_brace, len(text)):
            char = text[index]
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = ""
                continue
            if char in {"'", '"', "`"}:
                quote = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return text[open_brace + 1 : index]
        return None

    def _named_handler_body(self, text: str, name: str) -> str:
        declaration = re.search(
            rf"(?:\b(?:const|let|var)\s+{re.escape(name)}\s*=|\bfunction\s+{re.escape(name)}\s*\()",
            text,
        )
        if not declaration:
            return ""
        open_brace = text.find("{", declaration.end())
        if open_brace < 0:
            return ""
        depth = 0
        quote = ""
        escaped = False
        for index in range(open_brace, len(text)):
            char = text[index]
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = ""
                continue
            if char in {"'", '"', "`"}:
                quote = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return text[open_brace : index + 1]
        return ""
