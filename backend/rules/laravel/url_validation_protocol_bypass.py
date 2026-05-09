"""
URL validation protocol bypass rule.
"""

from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class UrlValidationProtocolBypassRule(Rule):
    id = "url-validation-protocol-bypass"
    name = "URL Validation Protocol Bypass"
    description = "Detects redirect/link request fields that rely on Laravel's broad url validation rule"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".php"]
    severity_weight = 8
    confidence = "high"
    fix_suggestion = (
        "Laravel's 'url' rule accepts file://, ftp://, and other dangerous protocols. Add starts_with:https,http "
        "validation or use a custom rule that explicitly allowlists safe protocols only."
    )
    examples = {
        "bad": "'redirect_url' => ['nullable', 'string', 'url'],",
        "good": "'redirect_url' => ['nullable', 'string', 'url', 'starts_with:https,http'],",
    }
    priority = 1
    group = "Security Hardening"
    applies_to = ["controller", "middleware"]
    references = ["OWASP A03:2021 - Injection", "CWE-601 URL Redirection to Untrusted Site"]
    related_rules = ["unsafe-redirect", "unsafe-external-redirect"]
    false_positive_notes = ""
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "security", "concern": "url-validation"}

    _FIELD_RE = re.compile(r"['\"](?P<field>[A-Za-z0-9_]+)['\"]\s*=>\s*\[", re.MULTILINE)
    _SENSITIVE_FIELDS = {
        "url",
        "redirect",
        "redirect_url",
        "return_url",
        "callback_url",
        "next",
        "destination",
        "link",
        "href",
        "target",
        "tracking_url",
        "campaign_url",
        "click_url",
    }
    _MEDIA_FIELDS = {"avatar_url", "image_url", "photo_url", "thumbnail_url"}
    _SAFE_RULE_RE = re.compile(r"(active_url|starts_with\s*:\s*https?|regex\s*:|Rule::|['\"]in:)", re.IGNORECASE)

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if not re.search(r"extends\s+(?:FormRequest|Request)\b", content):
            return []

        findings: list[Finding] = []
        for match in self._FIELD_RE.finditer(content):
            field = match.group("field")
            if field not in self._SENSITIVE_FIELDS or field in self._MEDIA_FIELDS:
                continue
            rule_block = self._array_block(content, match.start())
            if not re.search(r"['\"]url['\"]", rule_block):
                continue
            if self._SAFE_RULE_RE.search(rule_block):
                continue
            line = content.count("\n", 0, match.start()) + 1
            findings.append(
                self.create_finding(
                    title="URL validation allows unsafe protocols",
                    file=file_path,
                    line_start=line,
                    line_end=line,
                    context=field,
                    description=(
                        f"`{field}` uses Laravel's `url` rule without an HTTP/HTTPS protocol allowlist."
                    ),
                    why_it_matters=(
                        "The broad `url` validator can accept protocols that are unsafe for redirects or external "
                        "tracking links."
                    ),
                    suggested_fix=self.fix_suggestion,
                    tags=["laravel", "security", "redirect", "validation"],
                    confidence=0.9,
                ),
            )
        return findings

    @staticmethod
    def _array_block(content: str, start: int) -> str:
        end = content.find("],", start)
        if end == -1:
            end = content.find("]", start)
        if end == -1:
            end = min(len(content), start + 400)
        return content[start:end + 1]
