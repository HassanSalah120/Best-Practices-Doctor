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
        require_inertia_context = bool(self.get_threshold("require_inertia_context", True))
        require_global_share_context = bool(self.get_threshold("require_global_share_context", True))
        min_signal_count = int(self.get_threshold("min_signal_count", 1) or 1)
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)

        inertia_context, global_share_context, context_signals = self._detect_context(norm, low)
        if require_inertia_context and not inertia_context:
            return []
        if require_global_share_context and not global_share_context:
            return []
        if len(context_signals) < min_signal_count:
            return []

        raw_match = self._RAW_USER.search(text)
        array_dump_match = self._ARRAY_DUMP.search(text)
        match = raw_match or array_dump_match
        if not match:
            return []

        line = text.count("\n", 0, match.start()) + 1
        confidence = 0.91 if raw_match else 0.88
        if not global_share_context:
            confidence -= 0.12
        if confidence + 1e-9 < min_confidence:
            return []

        evidence = list(context_signals)
        evidence.append("raw_user_shared=true" if raw_match else "raw_user_array_dump=true")
        evidence.append(f"file={file_path}")
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
                confidence=confidence,
                evidence_signals=evidence,
            )
        ]

    def _detect_context(self, norm_path: str, content_lower: str) -> tuple[bool, bool, list[str]]:
        signals: list[str] = []
        inertia_context = False
        global_share_context = False

        if any(hint in norm_path for hint in self._PATH_HINTS):
            inertia_context = True
            signals.append("inertia_context=path_hint")
        if "inertia::share" in content_lower:
            inertia_context = True
            global_share_context = True
            signals.append("inertia_context=inertia_share_call")
        if "function share(" in content_lower or "parent::share(" in content_lower:
            inertia_context = True
            global_share_context = True
            signals.append("global_share_context=share_method")
        if not global_share_context and any(hint in content_lower for hint in self._FILE_HINTS):
            global_share_context = True
            signals.append("global_share_context=file_hint")

        return inertia_context, global_share_context, signals
