"""
Forced login without authorization rule.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class ForcedLoginWithoutAuthorizationRule(Rule):
    id = "forced-login-without-authorization"
    name = "Forced Login Without Authorization"
    description = "Detects Auth::login calls that are not preceded by an authorization check"
    category = Category.SECURITY
    default_severity = Severity.CRITICAL
    type = "regex"
    regex_file_extensions = [".php"]
    severity_weight = 10
    confidence = "medium"
    fix_suggestion = (
        "Add an authorization check before forcing login. Use $this->authorize(), Gate::allows(), "
        "or abort_if() with a policy check before calling Auth::login()."
    )
    examples = {
        "bad": "abort_if(! $clinic->isDemo(), 404);\nAuth::guard('web')->login($demoUser);",
        "good": "$this->authorize('access', $clinic);\nAuth::guard('web')->login($demoUser);",
    }
    priority = 1
    group = "Access Control"
    applies_to = ["controller", "service"]
    references = ["OWASP A01:2021 - Broken Access Control", "CWE-285 Improper Authorization"]
    related_rules = ["missing-auth-on-mutating-api-routes", "authorization-bypass-risk"]
    false_positive_notes = (
        "May false-positive on legitimate social login or SSO flows where authorization happens in middleware. "
        "Review the surrounding middleware stack before flagging."
    )
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "security", "concern": "forced-login"}

    _METHOD_RE = re.compile(
        r"(?P<signature>(?:public|protected|private)?\s*(?:static\s+)?function\s+"
        r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*(?::\s*[^{;]+)?\{)"
        r"(?P<body>.*?)\n\s*\}",
        re.DOTALL,
    )
    _LOGIN_RE = re.compile(r"(?:Auth::login\s*\(|auth\(\)->login\s*\(|Auth::guard\s*\([^)]*\)\s*->\s*login\s*\()")
    _AUTHZ_RE = re.compile(
        r"(\$this->authorize\s*\(|Gate::allows\s*\(|Gate::denies\s*\(|abort_if\s*\(\s*!\s*\$user->can\s*\(|"
        r"abort_unless\s*\(\s*\$user->can\s*\(|policy\s*\(|->can\s*\(|ensureGuest\s*\(|Auth::check\s*\()"
    )

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._is_test_file(file_path) or not self._is_controller_or_service(file_path):
            return []

        findings: list[Finding] = []
        for match in self._METHOD_RE.finditer(content):
            method_name = match.group("name")
            if self._is_standard_login_flow(file_path, method_name):
                continue

            body = match.group("body")
            if self._is_expected_account_entry_flow(file_path, content, body):
                continue
            lines = body.splitlines()
            body_has_authz = bool(self._AUTHZ_RE.search(body))
            for idx, line_text in enumerate(lines):
                if not self._LOGIN_RE.search(line_text):
                    continue
                preceding = "\n".join(lines[max(0, idx - 10):idx])
                if self._AUTHZ_RE.search(preceding):
                    continue
                if method_name.lower() in {"loginas", "impersonate"} and body_has_authz:
                    continue
                line = content.count("\n", 0, match.start()) + idx + 2
                findings.append(
                    self.create_finding(
                        title="Forced login is missing an authorization check",
                        file=file_path,
                        line_start=line,
                        line_end=line,
                        context=method_name,
                        description=(
                            f"`{method_name}` calls a Laravel login API without an authorization signal in the preceding lines."
                        ),
                        why_it_matters=(
                            "Forced login APIs can become authentication bypasses when reachable by users that should not "
                            "be able to assume the target identity."
                        ),
                        suggested_fix=self.fix_suggestion,
                        tags=["laravel", "security", "access-control", "authentication"],
                        confidence=0.74,
                    )
                )
        return findings

    @staticmethod
    def _is_test_file(file_path: str) -> bool:
        low = file_path.lower().replace("\\", "/")
        return "/tests/" in low or low.endswith("test.php")

    @staticmethod
    def _is_controller_or_service(file_path: str) -> bool:
        low = file_path.lower().replace("\\", "/")
        return "/controllers/" in low or "/services/" in low

    @staticmethod
    def _is_standard_login_flow(file_path: str, method_name: str) -> bool:
        low = file_path.lower().replace("\\", "/")
        return low.endswith("logincontroller.php") and method_name.lower() in {"login", "authenticate"}

    @staticmethod
    def _is_expected_account_entry_flow(file_path: str, content: str, body: str) -> bool:
        low = file_path.lower().replace("\\", "/")
        if "/controllers/auth/" in low and ("EnsuresGuestOnly" in content or "ensureGuest(" in body):
            return True
        if "event(new Registered" in body:
            return True
        if low.endswith("democontroller.php") and "Auth::check()" in body and "isDemo()" in body:
            return True
        return False
