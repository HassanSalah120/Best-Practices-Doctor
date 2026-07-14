from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics

from ._helpers import env_value, is_laravel_project, line_for_key, read_project_file


class AppDebugNotFalseInProductionRule(Rule):
    id = "app-debug-not-false-in-production"
    name = "App Debug Not False In Production"
    description = "Detects debug defaults that enable Laravel debug mode in production-facing configuration"
    category = Category.OPERATIONS
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "ast"
    severity_weight = 8
    confidence = "high"
    fix_suggestion = "Set 'debug' => env('APP_DEBUG', false) in config/app.php and ensure APP_DEBUG=false in .env.example."
    examples = {"bad": "'debug' => true", "good": "'debug' => env('APP_DEBUG', false)"}
    priority = 1
    group = "DevOps"
    applies_to = ["global"]
    references = ["OWASP A05:2021 - Security Misconfiguration"]
    related_rules = ["debug-exposure-risk"]
    false_positive_notes = "Development-only repositories may intentionally default debug mode on; production apps should not."
    detection_type = "cross-file"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "security", "concern": "debug-default"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if not is_laravel_project(facts):
            return []
        findings: list[Finding] = []
        app_config = read_project_file(facts, "config/app.php")
        match = re.search(r"""['\""]debug['\""]\s*=>\s*true\b""", app_config, re.IGNORECASE)
        if match:
            findings.append(
                self.create_finding(
                    title="config/app.php enables debug literally",
                    file="config/app.php",
                    line_start=app_config.count("\n", 0, match.start()) + 1,
                    context="config/app.php:debug",
                    description="The Laravel debug config is set to literal true instead of a safe env default.",
                    why_it_matters="Debug mode can expose stack traces, secrets, SQL, and application internals to users.",
                    suggested_fix=self.fix_suggestion,
                    confidence=0.96,
                    tags=["devops", "debug", "laravel"],
                    evidence_signals=["config_debug_literal_true=true"],
                ),
            )

        env_example = read_project_file(facts, ".env.example")
        if env_value(env_example, "APP_DEBUG") == "true":
            findings.append(
                self.create_finding(
                    title=".env.example defaults APP_DEBUG to true",
                    file=".env.example",
                    line_start=line_for_key(env_example, "APP_DEBUG"),
                    context=".env.example:APP_DEBUG",
                    description=".env.example sets APP_DEBUG=true as the default copied value.",
                    why_it_matters="Deployments copied from the example may accidentally expose debug output in production.",
                    suggested_fix=self.fix_suggestion,
                    confidence=0.94,
                    tags=["devops", "debug", "env"],
                    evidence_signals=["env_example_app_debug=true"],
                ),
            )
        return findings
