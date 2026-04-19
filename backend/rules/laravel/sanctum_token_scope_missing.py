"""
Sanctum Token Scope Missing Rule

Detects `createToken()` usage without explicit abilities/scope list.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class SanctumTokenScopeMissingRule(Rule):
    id = "sanctum-token-scope-missing"
    name = "Sanctum Token Scope Missing"
    description = "Detects Sanctum personal access token creation without explicit abilities"
    category = Category.SECURITY
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".php"]

    _ALLOWLIST_PATH_MARKERS = ("/tests/", "/test/", "/vendor/")
    _CREATE_TOKEN_CALL = re.compile(
        r"createToken\s*\((?P<args>[^)]*)\)",
        re.IGNORECASE | re.DOTALL,
    )
    _EMPTY_ABILITIES = re.compile(r"^\s*\[\s*\]\s*$")
    _SANCTUM_SIGNALS = ("sanctum", "personalaccesstoken", "auth:sanctum", "tokenscan")

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
        low_path = str(file_path or "").replace("\\", "/").lower()
        if any(marker in low_path for marker in self._ALLOWLIST_PATH_MARKERS):
            return []
        if "createtoken(" not in text.lower():
            return []

        require_sanctum_signal = bool(self.get_threshold("require_sanctum_signal", True))
        if require_sanctum_signal and not self._has_sanctum_signal(text, facts):
            return []

        require_multi_role_portal = bool(self.get_threshold("require_multi_role_portal_capability", False))
        if require_multi_role_portal and not self._capability_enabled(facts, "multi_role_portal"):
            return []

        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        findings: list[Finding] = []
        for match in self._CREATE_TOKEN_CALL.finditer(text):
            args_text = str(match.group("args") or "").strip()
            args = [part.strip() for part in args_text.split(",")]
            if len(args) >= 2:
                abilities = args[1]
                if abilities and not self._EMPTY_ABILITIES.match(abilities):
                    continue
            line = text.count("\n", 0, match.start()) + 1
            confidence = 0.84
            if confidence + 1e-9 < min_confidence:
                continue
            findings.append(
                self.create_finding(
                    title="Token creation missing explicit abilities/scope list",
                    context=f"{file_path}:{line}:createToken",
                    file=file_path,
                    line_start=line,
                    description=(
                        "Detected `createToken(...)` call without explicit abilities (or with an empty abilities array)."
                    ),
                    why_it_matters=(
                        "Unscoped API tokens can violate least-privilege boundaries and increase blast radius if leaked."
                    ),
                    suggested_fix=(
                        "Pass explicit token abilities when calling `createToken`, for example: "
                        "`createToken('portal', ['invoices:read', 'payments:create'])`."
                    ),
                    tags=["laravel", "security", "sanctum", "token", "least-privilege"],
                    confidence=confidence,
                    evidence_signals=[
                        "token_api=createToken",
                        "abilities_missing_or_empty=true",
                        f"sanctum_context={int(self._has_sanctum_signal(text, facts))}",
                    ],
                )
            )
            break
        return findings

    def _has_sanctum_signal(self, text: str, facts: Facts) -> bool:
        low = text.lower()
        if any(signal in low for signal in self._SANCTUM_SIGNALS):
            return True
        for route in facts.routes or []:
            middleware_text = " ".join(str(item or "").lower() for item in (route.middleware or []))
            if "sanctum" in middleware_text:
                return True
        return False

    def _capability_enabled(self, facts: Facts, key: str) -> bool:
        project_context = getattr(facts, "project_context", None)
        payload = None
        if project_context is not None:
            payload = (getattr(project_context, "capabilities", {}) or {}).get(key)
            if payload is None:
                payload = (getattr(project_context, "backend_capabilities", {}) or {}).get(key)
        return bool(isinstance(payload, dict) and payload.get("enabled"))

