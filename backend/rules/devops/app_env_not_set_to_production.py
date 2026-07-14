from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics

from ._helpers import env_value, is_laravel_project, line_for_key, read_project_file


class AppEnvNotSetToProductionRule(Rule):
    id = "app-env-not-set-to-production"
    name = "App Env Not Set To Production"
    description = "Detects environment defaults that encourage production servers to run in local/development mode"
    category = Category.OPERATIONS
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.RISK
    type = "ast"
    severity_weight = 5
    confidence = "medium"
    fix_suggestion = "Set APP_ENV=production in .env.example as the safe default. Override to local in personal .env files."
    examples = {"bad": "APP_ENV=local", "good": "APP_ENV=production"}
    priority = 2
    group = "DevOps"
    applies_to = ["global"]
    references = ["OWASP A05:2021 - Security Misconfiguration"]
    related_rules = ["app-debug-not-false-in-production"]
    false_positive_notes = "Will fire on development-only repos where production deployment is not the goal. Suppress with evidence if intentional."
    detection_type = "cross-file"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "security", "concern": "app-env-default"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if not is_laravel_project(facts):
            return []
        findings: list[Finding] = []
        env_example = read_project_file(facts, ".env.example")
        value = env_value(env_example, "APP_ENV")
        if value in {"local", "development"}:
            findings.append(
                self.create_finding(
                    title=".env.example defaults APP_ENV to development mode",
                    file=".env.example",
                    line_start=line_for_key(env_example, "APP_ENV"),
                    context=".env.example:APP_ENV",
                    description=f".env.example sets APP_ENV={value}.",
                    why_it_matters="Production servers copied from the example can inherit development behavior.",
                    suggested_fix=self.fix_suggestion,
                    confidence=0.78,
                    tags=["devops", "env", "laravel"],
                    evidence_signals=[f"env_example_app_env={value}"],
                ),
            )

        app_config = read_project_file(facts, "config/app.php")
        match = re.search(r"""['\""]env['\""]\s*=>\s*['\""](?:local|development)['\""]""", app_config, re.IGNORECASE)
        if match:
            findings.append(
                self.create_finding(
                    title="config/app.php hardcodes local environment",
                    file="config/app.php",
                    line_start=app_config.count("\n", 0, match.start()) + 1,
                    context="config/app.php:env",
                    description="The Laravel env config is hardcoded to local.",
                    why_it_matters="Hardcoded local environment defaults can disable production-safe behavior.",
                    suggested_fix="Use 'env' => env('APP_ENV', 'production') or another explicit production-safe default.",
                    confidence=0.8,
                    tags=["devops", "env", "laravel"],
                    evidence_signals=["config_env_literal_local=true"],
                ),
            )
        return findings
