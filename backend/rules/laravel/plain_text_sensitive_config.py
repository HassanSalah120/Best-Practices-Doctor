"""
Plain-text sensitive configuration rule.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class PlainTextSensitiveConfigRule(Rule):
    id = "plain-text-sensitive-config"
    name = "Plain-Text Sensitive Config"
    description = "Detects sensitive config keys assigned to literal strings instead of env() lookups"
    category = Category.SECURITY
    default_severity = Severity.CRITICAL
    type = "regex"
    regex_file_extensions = [".php"]

    _SENSITIVE_KEY = re.compile(
        r"(?P<key>[A-Za-z0-9_]*(secret|key|token|password)|stripe_[A-Za-z0-9_]+|aws_[A-Za-z0-9_]+)",
        re.IGNORECASE,
    )
    _ASSIGNMENT = re.compile(
        r"['\"](?P<key>[A-Za-z0-9_]+)['\"]\s*=>\s*['\"](?P<value>[^'\"]*)['\"]",
        re.IGNORECASE,
    )
    _IDENTIFIER_VALUE = re.compile(r"^[a-z0-9_.-]+$", re.IGNORECASE)
    _SECRET_VALUE_PREFIXES = ("sk_live_", "sk_test_", "pk_live_", "pk_test_", "akia", "ghp_")

    # Values that are identifiers/column names, not secrets
    _SAFE_IDENTIFIER_VALUES = {
        "users",  # password broker name
        "model_id",  # polymorphic column name
        "team_id",  # foreign key column name
        "spatie.permission.cache",  # cache key name
        "default",  # cache store name
        "null",  # explicit null
    }
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Remove the plain-text sensitive config risk and enforce the relevant Laravel/React security control at the boundary. Add a regression test that proves unsafe input or configuration is rejected.'
    examples = {}
    priority = 1
    group = 'Sensitive Data'
    applies_to = ['config']
    references = ['OWASP A05:2021 - Security Misconfiguration']
    related_rules = []
    false_positive_notes = ''
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'laravel', 'type': 'security', 'concern': 'plain-text-sensitive'}

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
        norm = (file_path or "").replace("\\", "/").lower()
        if "/config/" not in norm and not norm.startswith("config/"):
            return []

        findings: list[Finding] = []
        for i, line in enumerate((content or "").splitlines(), start=1):
            if "env(" in line.lower():
                continue
            match = self._ASSIGNMENT.search(line)
            if not match:
                continue
            key = str(match.groupdict().get("key") or "")
            value = str(match.groupdict().get("value") or "")
            if not self._SENSITIVE_KEY.search(key):
                continue
            if value == "" or value.lower() == "null":
                continue
            key_l = key.lower()
            value_l = value.lower()
            # Skip known safe identifier values (column names, config keys, etc.)
            if value_l in self._SAFE_IDENTIFIER_VALUES:
                continue
            # Skip values that look like column names or identifiers (not secrets)
            if value_l.endswith("_id") or value_l.endswith("_key") or value_l.endswith(".cache"):
                continue
            if key_l.endswith(("_foreign_key", "_pivot_key", "_morph_key")):
                continue
            if key_l in {"key", "store"} and self._IDENTIFIER_VALUE.match(value):
                continue
            if (
                self._IDENTIFIER_VALUE.match(value)
                and not self._is_high_risk_secret_key(key_l)
                and not any(value_l.startswith(prefix) for prefix in self._SECRET_VALUE_PREFIXES)
            ):
                continue
            findings.append(
                self.create_finding(
                    title="Sensitive config appears hardcoded in plain text",
                    context=f"{key} => '{value[:24]}'",
                    file=file_path,
                    line_start=i,
                    description=(
                        f"Detected sensitive config key `{key}` assigned to a literal string instead of env-driven configuration."
                    ),
                    why_it_matters="Hardcoded secrets in config files are easily leaked through source control or diagnostics.",
                    suggested_fix="Replace literal with `env('YOUR_KEY')` and store the value in environment secrets.",
                    confidence=0.94,
                    tags=["laravel", "security", "config", "secrets"],
                    evidence_signals=["sensitive_config_literal=true"],
                )
            )
        return findings

    def _is_high_risk_secret_key(self, key_l: str) -> bool:
        return any(
            token in key_l
            for token in ("secret", "token", "password", "private", "stripe_", "aws_")
        )
