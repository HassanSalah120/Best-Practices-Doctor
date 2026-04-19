"""
Weak Password Policy Validation Rule

Detects password validation rules that appear too weak for production auth flows.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class WeakPasswordPolicyValidationRule(Rule):
    id = "weak-password-policy-validation"
    name = "Weak Password Policy Validation"
    description = "Detects weak password validation in authentication/registration flows"
    category = Category.SECURITY
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".php"]

    _ALLOWLIST_PATH_MARKERS = ("/tests/", "/test/", "/vendor/")
    _PASSWORD_RULE = re.compile(
        r"['\"]password['\"]\s*=>\s*(?P<rules>\[[^\]]+\]|['\"][^'\"]+['\"])",
        re.IGNORECASE | re.DOTALL,
    )
    _STRONG_SIGNALS = (
        "password::",
        "rules\\password",
        "mixedcase",
        "letters()",
        "numbers()",
        "symbols()",
        "uncompromised",
    )
    _AUTH_CONTEXT_HINTS = ("register", "password", "reset", "auth", "fortify", "sanctum")
    _AUTHENTICATION_ONLY_PATH_HINTS = (
        "login",
        "signin",
        "sign-in",
        "authenticate",
        "session",
    )
    _PASSWORD_CREATION_HINTS = (
        "register",
        "storeuser",
        "createuser",
        "reset",
        "forgot",
        "new-password",
        "changepassword",
        "updateuser",
        "setpassword",
        "invitation",
        "invite",
    )
    _VALIDATION_CONTEXT_HINTS = (
        "validate(",
        "validator::make",
        " function rules(",
        " function rules():",
        "->rules(",
        "password::",
        "rules\\password",
        "fortify::passwordrules",
    )
    _NON_VALIDATION_RULE_TOKENS = ("hashed",)

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
        if not any(hint in low_path for hint in self._AUTH_CONTEXT_HINTS) and "'password'" not in text.lower():
            return []

        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        min_required_length = int(self.get_threshold("min_required_length", 8) or 8)
        findings: list[Finding] = []

        for match in self._PASSWORD_RULE.finditer(text):
            rules_text = str(match.group("rules") or "")
            rules_low = rules_text.lower()
            context_window = self._context_window(text, match.start(), match.end())
            if not self._is_validation_context(context_window) and not self._is_likely_validation_rules_string(
                rules_low, low_path
            ):
                continue
            if self._is_non_validation_password_mapping(rules_low):
                continue
            if "current_password" in rules_low:
                continue
            if self._is_authentication_only_password_check(low_path, text, rules_low, context_window):
                continue
            if any(signal in rules_low for signal in self._STRONG_SIGNALS):
                continue
            min_len = self._extract_min_len(rules_low)
            has_confirmed = "confirmed" in rules_low
            if min_len >= min_required_length and has_confirmed:
                continue
            line = text.count("\n", 0, match.start()) + 1
            confidence = 0.8 if has_confirmed else 0.86
            if confidence + 1e-9 < min_confidence:
                continue
            findings.append(
                self.create_finding(
                    title="Password validation policy appears weak",
                    context=f"{file_path}:{line}:password-rules",
                    file=file_path,
                    line_start=line,
                    description=(
                        "Detected password rules without strong complexity policy (and/or with short minimum length)."
                    ),
                    why_it_matters=(
                        "Weak password validation increases account takeover risk through credential stuffing and brute-force reuse."
                    ),
                    suggested_fix=(
                        "Use stronger password rules (for example `Password::min(12)->mixedCase()->numbers()->symbols()->uncompromised()`), "
                        "and keep `confirmed` where applicable."
                    ),
                    tags=["laravel", "security", "password", "auth"],
                    confidence=confidence,
                    evidence_signals=[
                        f"password_min_length={min_len}",
                        f"password_confirmed={int(has_confirmed)}",
                        "strong_password_signal=false",
                    ],
                )
            )
            break
        return findings

    def _extract_min_len(self, rules_low: str) -> int:
        match = re.search(r"min\s*:\s*(\d+)", rules_low)
        if not match:
            return 0
        try:
            return int(match.group(1))
        except ValueError:
            return 0

    def _context_window(self, text: str, start: int, end: int, span: int = 260) -> str:
        win_start = max(0, start - span)
        win_end = min(len(text), end + span)
        return text[win_start:win_end].lower()

    def _is_validation_context(self, context_window: str) -> bool:
        return any(hint in context_window for hint in self._VALIDATION_CONTEXT_HINTS)

    def _is_non_validation_password_mapping(self, rules_low: str) -> bool:
        compact = rules_low.strip().strip("'\"")
        if compact in self._NON_VALIDATION_RULE_TOKENS:
            return True
        return False

    def _is_likely_validation_rules_string(self, rules_low: str, low_path: str) -> bool:
        auth_request_path = (
            "/http/requests/" in low_path
            or "/http/controllers/auth/" in low_path
            or "/actions/auth/" in low_path
        )
        has_validation_tokens = (
            "required" in rules_low
            or "confirmed" in rules_low
            or "min:" in rules_low
            or "password::" in rules_low
        )
        return auth_request_path and has_validation_tokens

    def _is_authentication_only_password_check(self, low_path: str, text: str, rules_low: str, context_window: str) -> bool:
        scope = f"{low_path}\n{text.lower()}\n{context_window}"
        has_login_hint = any(hint in scope for hint in self._AUTHENTICATION_ONLY_PATH_HINTS)
        has_creation_hint = any(hint in scope for hint in self._PASSWORD_CREATION_HINTS)
        if not has_login_hint or has_creation_hint:
            return False

        has_identity_field = "'username'" in text.lower() or '"username"' in text.lower() or "'email'" in text.lower() or '"email"' in text.lower()
        if not has_identity_field:
            return False

        return "confirmed" not in rules_low and "password::" not in rules_low and "min:" not in rules_low
