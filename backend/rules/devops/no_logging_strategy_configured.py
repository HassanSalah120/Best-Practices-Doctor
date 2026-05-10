from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics

from ._helpers import env_value, is_laravel_project, project_file_exists, read_project_file


class NoLoggingStrategyConfiguredRule(Rule):
    id = "no-logging-strategy-configured"
    name = "No Logging Strategy Configured"
    description = "Detects Laravel logging defaults that rely only on local file channels"
    category = Category.MAINTAINABILITY
    default_severity = Severity.LOW
    default_classification = FindingClassification.ADVISORY
    type = "ast"
    severity_weight = 2
    confidence = "low"
    fix_suggestion = "Configure an external logging channel in config/logging.php. Consider Slack for critical errors or a structured logging service for production visibility."
    examples = {"bad": "LOG_CHANNEL=stack with channels ['single', 'daily']", "good": "LOG_CHANNEL=papertrail or a stack containing slack/papertrail/loggly"}
    priority = 4
    group = "DevOps"
    applies_to = ["global"]
    references = []
    related_rules = ["sensitive-data-logging"]
    false_positive_notes = "Many small projects legitimately log to files only. Low-medium signal - review manually."
    detection_type = "cross-file"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "quality", "concern": "logging-strategy"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if not is_laravel_project(facts):
            return []
        if not project_file_exists(facts, "config/logging.php"):
            return []
        config = read_project_file(facts, "config/logging.php")
        env_example = read_project_file(facts, ".env.example")
        env_channel = env_value(env_example, "LOG_CHANNEL")
        if env_channel and env_channel != "stack":
            return []
        if self._has_external_channel(config):
            return []
        if not self._default_is_stack(config):
            return []
        if not self._stack_is_local_only(config):
            return []

        return [
            self.create_finding(
                title="Logging defaults only use local file channels",
                file="config/logging.php",
                line_start=1,
                context="project:logging-strategy",
                description="config/logging.php appears to default to a stack containing only single/daily local file channels.",
                why_it_matters="Local-only logs can fill disk, disappear on server replacement, and hide production incidents from the team.",
                suggested_fix=self.fix_suggestion,
                confidence=0.48,
                tags=["devops", "logging", "observability"],
                evidence_signals=["logging_stack_local_only=true"],
            ),
        ]

    def _default_is_stack(self, content: str) -> bool:
        return bool(
            re.search(r"['\"]default['\"]\s*=>\s*['\"]stack['\"]", content or "", re.IGNORECASE)
            or re.search(r"env\s*\(\s*['\"]LOG_CHANNEL['\"]\s*,\s*['\"]stack['\"]", content or "", re.IGNORECASE),
        )

    def _stack_is_local_only(self, content: str) -> bool:
        low = (content or "").lower()
        if any(token in low for token in ("'single'", '"single"', "'daily'", '"daily"')):
            return True
        return not re.search(r"['\"]channels['\"]\s*=>\s*\[", content or "", re.IGNORECASE)

    def _has_external_channel(self, content: str) -> bool:
        low = (content or "").lower()
        return bool(any(token in low for token in ("slack", "papertrail", "loggly", "sentry", "bugsnag", "datadog", "webhook_url")))
