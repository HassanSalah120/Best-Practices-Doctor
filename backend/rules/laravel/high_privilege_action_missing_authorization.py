"""
High privilege action missing authorization rule.
"""

from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class HighPrivilegeActionMissingAuthorizationRule(Rule):
    id = "high-privilege-action-missing-authorization"
    name = "High Privilege Action Missing Authorization"
    description = "Detects emergency access, impersonation, or role elevation without explicit authorization"
    category = Category.SECURITY
    default_severity = Severity.CRITICAL
    type = "regex"
    regex_file_extensions = [".php"]
    severity_weight = 10
    confidence = "medium"
    fix_suggestion = (
        "High-privilege operations (emergency access, impersonation, role assignment) must be gated by an explicit "
        "authorization check. Add Gate::allows() or $this->authorize() before the privileged operation."
    )
    examples = {
        "bad": "$request->session()->put(['emergency_access_active' => true]);",
        "good": "Gate::allows('emergency-access') || abort(403);\n$request->session()->put(['emergency_access_active' => true]);",
    }
    priority = 1
    group = "Access Control"
    applies_to = ["service", "controller"]
    references = ["OWASP A01:2021 - Broken Access Control", "CWE-269 Improper Privilege Management"]
    related_rules = ["forced-login-without-authorization", "authorization-bypass-risk", "missing-policy-on-mutations"]
    false_positive_notes = (
        "Medium confidence because middleware or parent class may handle authorization. Verify the full request lifecycle "
        "before dismissing."
    )
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "security", "concern": "privilege-escalation"}

    _METHOD_RE = re.compile(
        r"(?P<signature>(?:public|protected|private)?\s*(?:static\s+)?function\s+"
        r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*(?::\s*[^{;]+)?\{)"
        r"(?P<body>.*?)\n\s*\}",
        re.DOTALL,
    )
    _HIGH_PRIVILEGE_RE = re.compile(
        r"((?:session\(\)|->session\(\))->put\s*\([\s\S]{0,240}emergency|"
        r"->assignRole\s*\(\s*['\"](?:admin|superadmin|system admin)['\"]|->givePermissionTo\s*\([^)]*admin|"
        r"Auth::loginUsingId\s*\(|forceFill\s*\(\s*\[[^\]]*['\"]is_admin['\"]\s*=>\s*true|->makeAdmin\s*\()",
        re.IGNORECASE | re.DOTALL,
    )
    _AUTHZ_RE = re.compile(
        r"(\$this->authorize\s*\(|Gate::allows\s*\(|Gate::denies\s*\(|abort_if\s*\(\s*!\s*\$user->can\s*\(|"
        r"abort_unless\s*\(\s*\$user->can\s*\(|abort_if\s*\(\s*!\s*auth\(\)->user\(\)->hasRole\s*\(|"
        r"->can\s*\(\s*['\"]|isSystemAdmin\s*\()",
        re.IGNORECASE,
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
        if re.search(r"class\s+\w*(Test|Seeder)\b", content):
            return []

        findings: list[Finding] = []
        for match in self._METHOD_RE.finditer(content):
            method_name = match.group("name")
            if method_name == "__construct":
                continue
            if re.search(r"(test|seed)", method_name, re.IGNORECASE):
                continue
            body = match.group("body")
            signal = self._HIGH_PRIVILEGE_RE.search(body)
            if not signal or self._AUTHZ_RE.search(body):
                continue
            if "Auth::loginUsingId" in signal.group(0) and self._is_expected_account_entry_flow(file_path, content, body):
                continue
            line = content.count("\n", 0, match.start() + signal.start()) + 1
            findings.append(
                self.create_finding(
                    title="High-privilege action is missing authorization",
                    file=file_path,
                    line_start=line,
                    line_end=line,
                    context=method_name,
                    description=(
                        f"`{method_name}` performs a high-privilege operation without an authorization signal in the method."
                    ),
                    why_it_matters=(
                        "Emergency access, impersonation, role assignment, and admin elevation can become privilege "
                        "escalation paths when not explicitly gated."
                    ),
                    suggested_fix=self.fix_suggestion,
                    tags=["laravel", "security", "access-control", "privilege"],
                    confidence=0.76,
                ),
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
    def _is_expected_account_entry_flow(file_path: str, content: str, body: str) -> bool:
        low = file_path.lower().replace("\\", "/")
        if "/controllers/auth/" not in low:
            return False
        has_guest_guard = "EnsuresGuestOnly" in content or "ensureGuest(" in body
        if not has_guest_guard:
            return False
        return bool(re.search(r"\b(onboard|register|create(?:Clinic|User)?|acceptInvitation)\b", body, re.IGNORECASE))
