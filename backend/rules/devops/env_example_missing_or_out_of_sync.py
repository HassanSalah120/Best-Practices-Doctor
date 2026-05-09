from __future__ import annotations

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule

from ._helpers import is_laravel_project, parse_env_keys, project_file_exists, read_project_file


class EnvExampleMissingOrOutOfSyncRule(Rule):
    id = "env-example-missing-or-out-of-sync"
    name = "Env Example Missing Or Out Of Sync"
    description = "Detects missing .env.example files or required keys absent from the example environment"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "ast"
    severity_weight = 8
    confidence = "high"
    fix_suggestion = "Create or update .env.example with all required keys. Never commit real values - use placeholders."
    examples = {
        "bad": ".env contains PAYMENT_SECRET=... but .env.example does not mention PAYMENT_SECRET.",
        "good": ".env.example contains PAYMENT_SECRET=change-me and real values stay only in .env.",
    }
    priority = 1
    group = "DevOps"
    applies_to = ["global"]
    references = []
    related_rules = ["env-committed-to-git", "plain-text-sensitive-config"]
    false_positive_notes = "Fresh installs without a local .env are not compared; only the missing .env.example file itself is reported."
    detection_type = "cross-file"
    analysis_cost = "medium"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "security", "concern": "env-example-sync"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if not is_laravel_project(facts):
            return []
        if not project_file_exists(facts, ".env.example"):
            return [
                self.create_finding(
                    title=".env.example is missing",
                    file=".env.example",
                    line_start=1,
                    context="project:.env.example",
                    description="The project root does not contain a .env.example file.",
                    why_it_matters="New developers and deployment systems need a safe, committed template of required configuration keys.",
                    suggested_fix=self.fix_suggestion,
                    confidence=0.96,
                    tags=["devops", "env", "onboarding"],
                    evidence_signals=["env_example_exists=false"],
                )
            ]

        if not project_file_exists(facts, ".env"):
            return []

        env_keys = parse_env_keys(read_project_file(facts, ".env"))
        example_keys = parse_env_keys(read_project_file(facts, ".env.example"))
        missing = sorted(env_keys - example_keys)
        if not missing:
            return []

        return [
            self.create_finding(
                title=".env.example is missing keys from .env",
                file=".env.example",
                line_start=1,
                context="project:.env.example:missing-keys",
                description=f".env contains keys missing from .env.example: {', '.join(missing[:10])}.",
                why_it_matters="Undocumented required configuration causes broken deployments and encourages secret sharing outside source control.",
                suggested_fix=self.fix_suggestion,
                confidence=0.94,
                tags=["devops", "env", "configuration"],
                evidence_signals=[f"missing_env_example_keys={','.join(missing[:10])}"],
                metadata={"missing_keys": missing},
            )
        ]
