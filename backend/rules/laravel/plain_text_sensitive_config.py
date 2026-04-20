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
