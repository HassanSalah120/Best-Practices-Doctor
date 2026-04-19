"""
Insecure postMessage Origin Wildcard Rule

Detects `postMessage(..., '*')` usage which allows untrusted target origins.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class InsecurePostMessageOriginWildcardRule(Rule):
    id = "insecure-postmessage-origin-wildcard"
    name = "Insecure postMessage Origin Wildcard"
    description = "Detects postMessage calls with wildcard target origin"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _POST_MESSAGE_WILDCARD = re.compile(
        r"\bpostMessage\s*\([^,\n]+,\s*(['\"])\\?\*\1",
        re.IGNORECASE,
    )
    _ALLOWLIST_PATH_MARKERS = ("__tests__", ".test.", ".spec.", ".stories.")

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
        low_path = str(file_path or "").lower().replace("\\", "/")
        if any(marker in low_path for marker in self._ALLOWLIST_PATH_MARKERS):
            return []

        match = self._POST_MESSAGE_WILDCARD.search(text)
        if not match:
            return []

        require_public_surface = bool(self.get_threshold("require_public_surface_capability", False))
        if require_public_surface and not self._has_public_surface_capability(facts):
            return []

        line = text.count("\n", 0, match.start()) + 1
        confidence = 0.97
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        if confidence + 1e-9 < min_confidence:
            return []

        return [
            self.create_finding(
                title="postMessage uses wildcard target origin",
                context=f"{file_path}:{line}:postMessage('*')",
                file=file_path,
                line_start=line,
                description="Detected `postMessage(..., '*')` with wildcard target origin.",
                why_it_matters=(
                    "Wildcard target origins can leak sensitive data to untrusted windows/frames and enable cross-origin message abuse."
                ),
                suggested_fix=(
                    "Use an explicit trusted origin (for example `window.location.origin` or allowlisted partner origin), "
                    "not `'*'`."
                ),
                tags=["react", "security", "postmessage", "origin"],
                confidence=confidence,
                evidence_signals=["postmessage_wildcard=true"],
            )
        ]

    def _has_public_surface_capability(self, facts: Facts) -> bool:
        return (
            self._capability_enabled(facts, "mixed_public_dashboard")
            or self._capability_enabled(facts, "public_marketing_site")
        )

    def _capability_enabled(self, facts: Facts, key: str) -> bool:
        project_context = getattr(facts, "project_context", None)
        payload = None
        if project_context is not None:
            payload = (getattr(project_context, "capabilities", {}) or {}).get(key)
            if payload is None:
                payload = (getattr(project_context, "backend_capabilities", {}) or {}).get(key)
        return bool(isinstance(payload, dict) and payload.get("enabled"))

