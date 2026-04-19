"""
Client Open Redirect Unvalidated Navigation Rule

Detects navigation targets sourced from URL params/search/hash without validation.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class ClientOpenRedirectUnvalidatedNavigationRule(Rule):
    id = "client-open-redirect-unvalidated-navigation"
    name = "Client Open Redirect Unvalidated Navigation"
    description = "Detects client-side navigation to unvalidated user-controlled targets"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _ALLOWLIST_PATH_MARKERS = ("__tests__", ".test.", ".spec.", ".stories.")
    _SOURCE_ASSIGN = re.compile(
        r"(?:const|let|var)\s+(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:new\s+URLSearchParams\([^)]*location\.search[^)]*\)\.get\(['\"](?:next|redirect|returnurl|target|url)['\"]\)|(?:window\.)?location\.(?:search|hash)|document\.referrer)",
        re.IGNORECASE,
    )
    _NAV_SINK = re.compile(
        r"(?:window\.location\.(?:href|assign|replace)\s*=\s*|window\.location\.(?:assign|replace)\s*\(\s*|navigate\s*\(\s*|router\.visit\s*\(\s*|inertia\.visit\s*\(\s*)(?P<var>[A-Za-z_][A-Za-z0-9_]*)",
        re.IGNORECASE,
    )
    _SAFE_SIGNALS = (
        ".startswith('/",
        ".startsWith('/",
        "window.location.origin",
        "new url(",
        ".origin ===",
        "allowlist",
        "whitelist",
        "safeRedirect".lower(),
        "resolveSafeRedirect".lower(),
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
        text = content or ""
        low_path = str(file_path or "").lower().replace("\\", "/")
        if any(marker in low_path for marker in self._ALLOWLIST_PATH_MARKERS):
            return []

        require_public_surface = bool(self.get_threshold("require_public_surface_capability", False))
        if require_public_surface and not self._has_public_surface_capability(facts):
            return []

        source_vars = {str(match.group("var") or "").strip() for match in self._SOURCE_ASSIGN.finditer(text)}
        if not source_vars:
            return []

        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        for sink in self._NAV_SINK.finditer(text):
            var_name = str(sink.group("var") or "").strip()
            if not var_name or var_name not in source_vars:
                continue
            window = self._window(text, sink.start(), before=26, after=18).lower()
            if any(signal.lower() in window for signal in self._SAFE_SIGNALS):
                continue

            line = text.count("\n", 0, sink.start()) + 1
            confidence = 0.87
            if confidence + 1e-9 < min_confidence:
                continue
            return [
                self.create_finding(
                    title="Navigation target may be unvalidated (client open redirect risk)",
                    context=f"{file_path}:{line}:{var_name}",
                    file=file_path,
                    line_start=line,
                    description=(
                        f"Detected navigation sink using `{var_name}` derived from URL/search/referrer without visible origin/path validation."
                    ),
                    why_it_matters=(
                        "Client-side open redirects can enable phishing chains, token leakage, and unsafe cross-origin navigation flows."
                    ),
                    suggested_fix=(
                        "Validate redirect targets against same-origin or strict allowlist rules, and default to a safe internal path when invalid."
                    ),
                    tags=["react", "security", "open-redirect", "navigation"],
                    confidence=confidence,
                    evidence_signals=[
                        f"redirect_var={var_name}",
                        "source=url_search_or_referrer",
                        "validation_signal_missing=true",
                    ],
                )
            ]
        return []

    def _window(self, text: str, start_idx: int, before: int = 24, after: int = 12) -> str:
        lines = text.splitlines()
        line = text.count("\n", 0, start_idx) + 1
        start_line = max(0, line - before - 1)
        end_line = min(len(lines), line + after)
        return "\n".join(lines[start_line:end_line])

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

