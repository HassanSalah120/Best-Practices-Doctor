"""
Console command missing tenant scope rule.
"""

from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class ConsoleCommandMissingTenantScopeRule(Rule):
    id = "console-command-missing-tenant-scope"
    name = "Console Command Missing Tenant Scope"
    description = "Detects Artisan commands that query tenant data without clinic or tenant scoping"
    category = Category.OPERATIONS
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".php"]
    severity_weight = 8
    confidence = "medium"
    fix_suggestion = (
        "Artisan commands in multi-tenant apps must scope all queries by tenant. Add ->where('clinic_id', $clinicId) "
        "or use a global scope. Process tenant by tenant using chunk()."
    )
    examples = {
        "bad": "return Invoice::whereIn('status', ['overdue'])->get();",
        "good": "return Invoice::where('clinic_id', $clinic->id)->whereIn('status', ['overdue'])->get();",
    }
    priority = 1
    group = "Access Control"
    applies_to = ["php-class"]
    references = ["OWASP A01:2021 - Broken Access Control", "CWE-284 Improper Access Control"]
    related_rules = ["tenant-scope-enforcement", "missing-tenant-middleware", "multi-tenant-boundary-violation"]
    false_positive_notes = (
        "Will false-positive on single-tenant apps or commands that intentionally operate across all tenants "
        "(for example, superadmin reporting). Add a suppression comment if intentional."
    )
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "security", "concern": "tenant-scope"}

    _QUERY_RE = re.compile(r"\b(?P<model>[A-Z][A-Za-z0-9_]*)::(?:where[A-Za-z]*|all|get)\s*\(|DB::table\s*\(")
    _CLASS_RE = re.compile(r"class\s+(?P<name>[A-Za-z_]\w*)\s+extends\s+Command")
    _GLOBAL_MODELS = {"User", "Setting", "Config", "Permission", "Role"}
    _SYSTEM_COMMAND_WORDS = ("Superadmin", "Global", "System", "Maintenance", "Migration", "Install", "Setup")
    _TENANT_SCOPE_RE = re.compile(
        r"(clinic_id|tenant_id|organization_id|company_id|team_id|whereNull\s*\(\s*['\"]clinic_id['\"]|"
        r"->forTenant\s*\(|->forClinic\s*\(|->whereTenant\s*\()",
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
        class_match = self._CLASS_RE.search(content)
        if not class_match:
            return []
        if any(word in class_match.group("name") for word in self._SYSTEM_COMMAND_WORDS):
            return []

        findings: list[Finding] = []
        for match in self._QUERY_RE.finditer(content):
            model = match.groupdict().get("model") or ""
            if model in self._GLOBAL_MODELS:
                continue
            statement = self._statement_around(content, match.start())
            if self._TENANT_SCOPE_RE.search(statement):
                continue
            if "chunk(" in statement and re.search(r"\$(clinic|tenant|organization|team)\b", statement, re.IGNORECASE):
                continue
            line = content.count("\n", 0, match.start()) + 1
            findings.append(
                self.create_finding(
                    title="Artisan command query is missing tenant scope",
                    file=file_path,
                    line_start=line,
                    line_end=line,
                    context=class_match.group("name"),
                    description=(
                        "This Artisan command runs an Eloquent/DB query without an obvious clinic, tenant, or organization scope."
                    ),
                    why_it_matters=(
                        "Scheduled commands often run system-wide. An unscoped tenant query can leak data or send actions "
                        "across all tenants."
                    ),
                    suggested_fix=self.fix_suggestion,
                    tags=["laravel", "security", "multi-tenant", "console"],
                    confidence=0.76,
                ),
            )
        return findings[:1]

    @staticmethod
    def _statement_around(content: str, start: int) -> str:
        before = content.rfind(";", 0, start)
        after = content.find(";", start)
        if after == -1:
            after = min(len(content), start + 500)
        return content[before + 1:after + 1]
