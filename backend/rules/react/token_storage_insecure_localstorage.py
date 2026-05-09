"""
Token Storage Insecure LocalStorage Rule

Detects JWT/access/session token storage in browser localStorage/sessionStorage.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class TokenStorageInsecureLocalStorageRule(Rule):
    id = "token-storage-insecure-localstorage"
    name = "Token Storage Insecure LocalStorage"
    description = "Detects sensitive token persistence in localStorage/sessionStorage"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _SET_ITEM = re.compile(
        r"\b(?:localStorage|sessionStorage)\.setItem\s*\(\s*(['\"])(?P<key>[^'\"]+)\1\s*,",
        re.IGNORECASE,
    )
    _PROPERTY_ASSIGN = re.compile(
        r"\b(?:localStorage|sessionStorage)\.(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*=",
        re.IGNORECASE,
    )
    _SENSITIVE_KEY_TOKENS = ("token", "jwt", "auth", "bearer", "refresh")
    _EXACT_SESSION_KEYS = {"session", "session_id", "sessionid", "sid"}
    _CLIENT_GENERATED_ID_SIGNAL = re.compile(
        r"\b(?:crypto\.randomUUID|randomUUID|uuidv4|uuid)\s*\(",
        re.IGNORECASE,
    )
    _AUTH_VALUE_SIGNAL = re.compile(
        r"\b(?:access[_-]?token|refresh[_-]?token|jwt|bearer|auth[_-]?token|id[_-]?token)\b",
        re.IGNORECASE,
    )
    _SAFE_KEY_EXCLUSIONS = ("theme", "locale", "language", "timezone", "dismissed", "onboarding", "layout")
    _ALLOWLIST_PATH_MARKERS = (
        "__tests__",
        ".test.",
        ".spec.",
        ".stories.",
        "/public/dist/",
        "/dist/assets/",
        "/build/assets/",
    )
    severity_weight = 0
    confidence = 'high'
    fix_suggestion = 'Remove the token storage insecure localstorage risk and enforce the relevant Laravel/React security control at the boundary. Add a regression test that proves unsafe input or configuration is rejected.'
    examples = {}
    priority = 1
    group = 'Sensitive Data'
    applies_to = ['react-component']
    references = ['OWASP A02:2021 - Cryptographic Failures', 'CWE-798']
    related_rules = []
    false_positive_notes = ''
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'security', 'concern': 'token-storage-insecure'}

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
        if "localstorage" not in text.lower() and "sessionstorage" not in text.lower():
            return []

        require_public_surface = bool(self.get_threshold("require_public_surface_capability", False))
        if require_public_surface and not self._has_public_surface_capability(facts):
            return []

        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)

        for match, key in self._iter_storage_keys(text):
            key_low = key.lower()
            if any(token in key_low for token in self._SAFE_KEY_EXCLUSIONS):
                continue
            if not self._is_sensitive_storage_key(key_low, text, match.start()):
                continue
            line = text.count("\n", 0, match.start()) + 1
            confidence = 0.92
            if confidence + 1e-9 < min_confidence:
                continue
            return [
                self.create_finding(
                    title="Sensitive token stored in browser storage",
                    context=f"{file_path}:{line}:{key}",
                    file=file_path,
                    line_start=line,
                    description=(
                        f"Detected `{key}` stored via browser storage (`localStorage`/`sessionStorage`)."
                    ),
                    why_it_matters=(
                        "Browser storage is accessible to injected scripts; storing auth tokens there increases XSS-driven account hijack risk."
                    ),
                    suggested_fix=(
                        "Prefer HttpOnly secure cookies for session/auth tokens. If token storage is unavoidable, minimize lifetime and scope "
                        "and harden CSP/XSS defenses."
                    ),
                    tags=["react", "security", "token", "localstorage", "session-hijack"],
                    confidence=confidence,
                    evidence_signals=[
                        f"storage_key={key}",
                        "browser_storage=local_or_session",
                        "sensitive_token_key=true",
                    ],
                )
            ]
        return []

    def _is_sensitive_storage_key(self, key_low: str, text: str, offset: int) -> bool:
        if any(token in key_low for token in self._SENSITIVE_KEY_TOKENS):
            return True

        if "session" not in key_low and key_low not in self._EXACT_SESSION_KEYS:
            return False

        if key_low in self._EXACT_SESSION_KEYS:
            return True

        window = text[max(0, offset - 300): min(len(text), offset + 300)]
        if self._AUTH_VALUE_SIGNAL.search(window):
            return True

        # Namespaced app session identifiers are often client-generated grouping IDs,
        # not authentication credentials. Do not flag them unless auth/token evidence
        # appears near the storage call.
        if key_low.endswith("_session_id") or key_low.endswith("-session-id") or key_low.endswith("sessionid"):
            return not self._CLIENT_GENERATED_ID_SIGNAL.search(window)

        return True

    def _iter_storage_keys(self, text: str) -> list[tuple[re.Match[str], str]]:
        out: list[tuple[re.Match[str], str]] = []
        for match in self._SET_ITEM.finditer(text):
            out.append((match, str(match.group("key") or "").strip()))
        for match in self._PROPERTY_ASSIGN.finditer(text):
            out.append((match, str(match.group("key") or "").strip()))
        out.sort(key=lambda item: item[0].start())
        return out

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

