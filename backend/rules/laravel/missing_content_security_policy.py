"""
Missing Content Security Policy rule.
"""

from __future__ import annotations

import re
from pathlib import Path

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class MissingContentSecurityPolicyRule(Rule):
    id = "missing-content-security-policy"
    name = "Missing Content Security Policy"
    description = "Detects missing CSP middleware/header registration in Laravel bootstrap/kernel paths"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".php"]

    _CSP_SIGNAL = re.compile(
        r"content-security-policy",
        re.IGNORECASE,
    )
    _CSP_REGISTRATION_SIGNAL = re.compile(
        r"(content-security-policy|contentsecuritypolicy|cspmiddleware|spatie\\csp)",
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
    fix_suggestion = 'Remove the missing content security policy risk and enforce the relevant Laravel/React security control at the boundary. Add a regression test that proves unsafe input or configuration is rejected.'
    examples = {}
    priority = 1
    group = 'Access Control'
    applies_to = ['global']
    references = ['OWASP A05:2021 - Security Misconfiguration']
    related_rules = []
    false_positive_notes = 'May be a false positive when protection is enforced by upstream middleware, shared policy, or infrastructure not visible to the scanner.'
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'laravel', 'type': 'security', 'concern': 'content-security-policy'}

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

        if self._project_has_csp_signal(facts=facts, current_path=norm, current_content=content):
            return []

        payload = content or ""
        if "middleware" not in payload.lower() and "headers" not in payload.lower():
            return []
        return [
            self.create_finding(
                title="Content Security Policy appears missing",
                context="CSP middleware/header not found",
                file=file_path,
                line_start=1,
                description="Could not find CSP middleware registration or `Content-Security-Policy` header handling.",
                why_it_matters="CSP reduces XSS blast radius by constraining allowed script/style sources.",
                suggested_fix=(
                    "Register CSP middleware or set `Content-Security-Policy` response headers in your security middleware stack."
                ),
                confidence=0.8,
                tags=["laravel", "security", "headers", "csp"],
                evidence_signals=[
                    "csp_header_missing=true",
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

    def _project_has_csp_signal(self, *, facts: Facts, current_path: str, current_content: str) -> bool:
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
            if self._CSP_SIGNAL.search(text) or self._CSP_REGISTRATION_SIGNAL.search(text):
                return True
        return False

    def _read_project_file(self, *, facts: Facts, rel_path: str, current_path: str, current_content: str) -> str:
        if rel_path == current_path:
            return current_content or ""
        project_root = Path(str(getattr(facts, "project_path", "") or "."))
        normalized = str(rel_path or "").replace("\\", "/").lower()
        original_path = next(
            (
                str(path or "").replace("\\", "/")
                for path in (getattr(facts, "files", []) or [])
                if str(path or "").replace("\\", "/").lower() == normalized
            ),
            rel_path,
        )
        candidate = project_root / original_path
        try:
            if candidate.exists():
                return candidate.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return ""
        return ""
