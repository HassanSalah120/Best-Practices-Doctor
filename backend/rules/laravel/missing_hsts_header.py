"""
Missing HSTS header rule.
"""

from __future__ import annotations

import re
from pathlib import Path

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class MissingHstsHeaderRule(Rule):
    id = "missing-hsts-header"
    name = "Missing HSTS Header"
    description = "Detects missing Strict-Transport-Security hardening in middleware/header configuration"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".php"]

    _HSTS_SIGNAL = re.compile(r"strict-transport-security", re.IGNORECASE)
    _HSTS_REGISTRATION_SIGNAL = re.compile(
        r"(securityheadersmiddleware|hsts|stricttransportsecurity)",
        re.IGNORECASE,
    )
    _TARGET_FILES = (
        "app/http/kernel.php",
        "bootstrap/app.php",
        "app/http/middleware",
    )
    _PRIMARY_FILES = ("bootstrap/app.php", "app/http/kernel.php")
    severity_weight = 0
    confidence = 'high'
    fix_suggestion = 'Remove the missing hsts header risk and enforce the relevant Laravel/React security control at the boundary. Add a regression test that proves unsafe input or configuration is rejected.'
    examples = {}
    priority = 1
    group = 'Security Hardening'
    applies_to = ['config']
    references = ['OWASP A05:2021 - Security Misconfiguration']
    related_rules = []
    false_positive_notes = 'May be a false positive when protection is enforced by upstream middleware, shared policy, or infrastructure not visible to the scanner.'
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'laravel', 'type': 'security', 'concern': 'hsts-header'}

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
        if not any(token in norm for token in self._TARGET_FILES):
            return []
        if not self._is_primary_target(norm, facts):
            return []

        if self._project_has_hsts_signal(facts=facts, current_path=norm, current_content=content):
            return []

        if "middleware" not in (content or "").lower() and "headers" not in (content or "").lower():
            return []

        return [
            self.create_finding(
                title="HSTS header hardening appears missing",
                context="Strict-Transport-Security not configured",
                file=file_path,
                line_start=1,
                description=(
                    "Could not find `Strict-Transport-Security` header handling in middleware/kernel bootstrapping."
                ),
                why_it_matters=(
                    "Without HSTS, browsers may downgrade to insecure HTTP, enabling man-in-the-middle attacks."
                ),
                suggested_fix=(
                    "Add a security headers middleware that sets `Strict-Transport-Security` for HTTPS responses."
                ),
                confidence=0.82,
                tags=["laravel", "security", "headers", "hsts"],
                evidence_signals=[
                    "hsts_header_missing=true",
                    "scan_scope=project_security_headers",
                ],
            ),
        ]

    def _is_primary_target(self, normalized_path: str, facts: Facts) -> bool:
        known = {
            str(path or "").replace("\\", "/").lower()
            for path in (getattr(facts, "files", []) or [])
        }
        for primary in self._PRIMARY_FILES:
            if primary in known:
                return normalized_path == primary
        return normalized_path in set(self._PRIMARY_FILES)

    def _project_has_hsts_signal(self, *, facts: Facts, current_path: str, current_content: str) -> bool:
        files = {
            str(path or "").replace("\\", "/").lower()
            for path in (getattr(facts, "files", []) or [])
            if any(token in str(path or "").replace("\\", "/").lower() for token in self._TARGET_FILES)
        }
        files.add(current_path)

        for rel in sorted(files):
            text = self._read_project_file(facts=facts, rel_path=rel, current_path=current_path, current_content=current_content)
            if not text:
                continue
            if self._HSTS_SIGNAL.search(text) or self._HSTS_REGISTRATION_SIGNAL.search(text):
                return True
        return False

    def _read_project_file(self, *, facts: Facts, rel_path: str, current_path: str, current_content: str) -> str:
        if rel_path == current_path:
            return current_content or ""
        project_root = Path(str(getattr(facts, "project_path", "") or "."))
        candidate = project_root / rel_path
        try:
            if candidate.exists():
                return candidate.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return ""
        return ""
