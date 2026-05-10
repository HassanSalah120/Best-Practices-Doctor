from __future__ import annotations

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics

from ._helpers import is_laravel_project, project_file_exists, read_project_file


class EnvCommittedToGitRule(Rule):
    id = "env-committed-to-git"
    name = "Env Committed To Git Risk"
    description = "Detects projects whose .gitignore does not explicitly ignore the real .env file"
    category = Category.SECURITY
    default_severity = Severity.CRITICAL
    default_classification = FindingClassification.RISK
    type = "ast"
    severity_weight = 10
    confidence = "high"
    fix_suggestion = "Add .env to .gitignore immediately. If .env was ever committed, rotate all secrets it contained."
    examples = {"bad": ".gitignore omits .env", "good": ".gitignore contains .env or /.env"}
    priority = 1
    group = "DevOps"
    applies_to = ["global"]
    references = ["OWASP A02:2021 - Cryptographic Failures"]
    related_rules = ["env-example-missing-or-out-of-sync", "hardcoded-secrets"]
    false_positive_notes = ".env.example should remain committed; this rule only checks the real .env file."
    detection_type = "cross-file"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "security", "concern": "env-gitignore"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if not is_laravel_project(facts):
            return []
        content = read_project_file(facts, ".gitignore")
        if project_file_exists(facts, ".gitignore") and self._ignores_env(content):
            return []
        return [
            self.create_finding(
                title=".env is not explicitly ignored by git",
                file=".gitignore",
                line_start=1,
                context="project:.gitignore:.env",
                description=".gitignore is missing an explicit .env ignore entry.",
                why_it_matters=".env commonly contains credentials, tokens, and database passwords that must never be committed.",
                suggested_fix=self.fix_suggestion,
                confidence=0.97,
                tags=["devops", "secrets", "gitignore"],
                evidence_signals=["gitignore_ignores_env=false"],
            ),
        ]

    def _ignores_env(self, content: str) -> bool:
        for line in (content or "").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped in {".env", "/.env"}:
                return True
        return False
