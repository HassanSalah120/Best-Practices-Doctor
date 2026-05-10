from __future__ import annotations

import json

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics

from ._helpers import is_laravel_project, iter_project_files, project_file_exists, read_project_file


class MissingQueueWorkerSupervisionRule(Rule):
    id = "missing-queue-worker-supervision"
    name = "Missing Queue Worker Supervision"
    description = "Detects Laravel queue usage without Horizon or supervisor worker restart configuration"
    category = Category.PERFORMANCE
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "ast"
    severity_weight = 8
    confidence = "medium"
    fix_suggestion = "Install Laravel Horizon for queue monitoring or add a Supervisord config that restarts queue workers automatically on failure."
    examples = {"bad": "app/Jobs/SendEmail.php exists but no Horizon or supervisor config", "good": "laravel/horizon is installed"}
    priority = 2
    group = "DevOps"
    applies_to = ["global"]
    references = []
    related_rules = ["job-missing-retry-policy", "queue-job-missing-failure-handling"]
    false_positive_notes = "Managed platforms may supervise queue workers outside the repository. Document that external process supervision if intentional."
    detection_type = "cross-file"
    analysis_cost = "medium"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "performance", "concern": "queue-supervision"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if not is_laravel_project(facts):
            return []
        if not self._uses_queues(facts):
            return []
        if self._has_supervision(facts):
            return []
        return [
            self.create_finding(
                title="Queue workers have no repository-visible supervision",
                file="app/Jobs",
                line_start=1,
                context="project:queue-supervision",
                description="Queue usage was detected, but no Laravel Horizon or Supervisord queue worker configuration was found.",
                why_it_matters="Without worker supervision, crashed workers can stop processing jobs silently.",
                suggested_fix=self.fix_suggestion,
                confidence=0.76,
                tags=["devops", "queues", "supervision"],
                evidence_signals=["queue_usage_detected=true", "queue_supervision_detected=false"],
            ),
        ]

    def _uses_queues(self, facts: Facts) -> bool:
        composer = read_project_file(facts, "composer.json").lower()
        if any(token in composer for token in ("laravel/horizon", "laravel/queue", "enqueue/", "queue")):
            return True
        if any(path.as_posix().endswith(".php") for path in iter_project_files(facts, "*.php") if "/app/Jobs/" in f"/{path.as_posix()}"):
            return True
        for path in iter_project_files(facts, "*.php"):
            try:
                if "ShouldQueue" in path.read_text(encoding="utf-8", errors="replace"):
                    return True
            except Exception:
                continue
        return False

    def _has_supervision(self, facts: Facts) -> bool:
        composer_text = read_project_file(facts, "composer.json")
        try:
            composer = json.loads(composer_text or "{}")
        except Exception:
            composer = {}
        packages = {}
        if isinstance(composer, dict):
            packages.update(composer.get("require", {}) or {})
            packages.update(composer.get("require-dev", {}) or {})
        if "laravel/horizon" in {str(k).lower() for k in packages}:
            return True
        if project_file_exists(facts, "config/horizon.php"):
            return True
        for path in iter_project_files(facts, "*.conf"):
            try:
                text = path.read_text(encoding="utf-8", errors="replace").lower()
            except Exception:
                continue
            if "[program:" in text and "php artisan queue:work" in text:
                return True
        return False
