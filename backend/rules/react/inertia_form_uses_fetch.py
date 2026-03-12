"""
Inertia Form Uses Fetch Rule

Detects Inertia page forms that submit with fetch/axios instead of `useForm`.
"""

from __future__ import annotations

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class InertiaFormUsesFetchRule(Rule):
    id = "inertia-form-uses-fetch"
    name = "Inertia Form Uses Fetch"
    description = "Detects Inertia page forms using fetch/axios instead of useForm"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types = ["laravel_inertia_react"]
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

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
        norm = (file_path or "").replace("\\", "/").lower()
        if "/resources/js/pages/" not in f"/{norm}":
            return []

        text = content or ""
        if "<form" not in text:
            return []
        if "useForm(" in text:
            return []
        if "fetch(" not in text and "axios." not in text:
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
            )
        ]
