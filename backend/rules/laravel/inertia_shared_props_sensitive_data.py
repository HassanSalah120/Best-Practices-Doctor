"""
Inertia Shared Props Sensitive Data Rule

Detects raw authenticated user objects shared globally with Inertia.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class InertiaSharedPropsSensitiveDataRule(Rule):
    id = "inertia-shared-props-sensitive-data"
    name = "Inertia Shared Props Sensitive Data"
    description = "Detects raw user objects shared globally with Inertia props"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types = ["laravel_inertia_react", "laravel_inertia_vue"]
    regex_file_extensions = [".php"]

    _PATH_HINTS = ("handleinertiarequests.php", "/middleware/", "/providers/")
    _FILE_HINTS = ("inertia::share", "function share(", "parent::share(")
    _RAW_USER = re.compile(
        r"(['\"](?:auth\.user|user)['\"]\s*=>\s*(?:\$request->user\s*\(\s*\)|auth\s*\(\s*\)\s*->\s*user\s*\(\s*\)|Auth::user\s*\(\s*\))(?!\s*(?:\?->|->)\s*only\s*\())",
        re.IGNORECASE,
    )
    _ARRAY_DUMP = re.compile(
        r"(['\"](?:auth\.user|user)['\"]\s*=>\s*(?:\$request->user\s*\(\s*\)|auth\s*\(\s*\)\s*->\s*user\s*\(\s*\)|Auth::user\s*\(\s*\))\s*(?:\?->|->)\s*toArray\s*\()",
        re.IGNORECASE,
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
        norm = (file_path or "").replace("\\", "/").lower()
        text = content or ""
        low = text.lower()
        if not any(hint in norm for hint in self._PATH_HINTS) and not any(hint in low for hint in self._FILE_HINTS):
            return []

        match = self._RAW_USER.search(text) or self._ARRAY_DUMP.search(text)
        if not match:
            return []

        line = text.count("\n", 0, match.start()) + 1
        return [
            self.create_finding(
                title="Inertia shared props expose the raw authenticated user object",
                context=f"{file_path}:{line}:share",
                file=file_path,
                line_start=line,
                description=(
                    "Detected a global Inertia shared prop that returns the authenticated user object directly "
                    "instead of whitelisting specific fields."
                ),
                why_it_matters=(
                    "Sharing the full user model with every Inertia response can leak hidden attributes, "
                    "relationship data, or newly-added sensitive fields to the frontend."
                ),
                suggested_fix=(
                    "Share only explicit fields, for example `fn () => $request->user()?->only('id', 'name', 'email')`, "
                    "instead of returning the full model or `toArray()` result."
                ),
                tags=["laravel", "inertia", "security", "shared-props"],
                confidence=0.9,
                evidence_signals=["raw_user_shared=true", f"file={file_path}"],
            )
        ]
