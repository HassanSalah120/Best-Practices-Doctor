"""
Client bundle API key leakage rule.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class ApiKeyInClientBundleRule(Rule):
    id = "api-key-in-client-bundle"
    name = "API Key In Client Bundle"
    description = "Detects likely secret/API key literals embedded in client-side source files"
    category = Category.SECURITY
    default_severity = Severity.CRITICAL
    type = "regex"
    regex_file_extensions = [".tsx", ".ts", ".jsx", ".js"]

    _KEY_PATTERNS = [
        re.compile(r"sk_live_[A-Za-z0-9]{8,}", re.IGNORECASE),
        re.compile(r"pk_live_[A-Za-z0-9]{8,}", re.IGNORECASE),
        re.compile(r"sk_test_[A-Za-z0-9]{8,}", re.IGNORECASE),
        re.compile(r"AKIA[0-9A-Z]{12,}", re.IGNORECASE),
        re.compile(r"API_KEY\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
    ]

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
        if norm.endswith(".env") or ".env." in norm:
            return []

        findings: list[Finding] = []
        lines = (content or "").splitlines()
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue
            for pattern in self._KEY_PATTERNS:
                if not pattern.search(line):
                    continue
                findings.append(
                    self.create_finding(
                        title="Potential API key exposed in client bundle code",
                        context=stripped[:100],
                        file=file_path,
                        line_start=i,
                        description="Detected key-like literal in client source that may be shipped to browsers.",
                        why_it_matters=(
                            "Secrets in frontend bundles are publicly retrievable and can be abused immediately."
                        ),
                        suggested_fix="Move secret usage to server-side code and expose only scoped/public tokens.",
                        confidence=0.95,
                        tags=["react", "security", "secrets", "frontend"],
                        evidence_signals=["client_secret_literal=true"],
                    )
                )
                break
        return findings
