"""
Upload Size Limit Missing Rule

Detects upload validation rules missing explicit max size constraints.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class UploadSizeLimitMissingRule(Rule):
    id = "upload-size-limit-missing"
    name = "Upload Size Limit Missing"
    description = "Detects upload validation without explicit max file size"
    category = Category.SECURITY
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".php"]

    _ALLOWLIST_PATH_MARKERS = ("/tests/", "/test/", "/vendor/")
    _UPLOAD_RULE = re.compile(
        r"['\"](?P<field>[A-Za-z0-9_\-]+)['\"]\s*=>\s*(?P<rules>\[[^\]]+\]|['\"][^'\"]+['\"])",
        re.IGNORECASE | re.DOTALL,
    )
    _UPLOAD_SIGNAL = re.compile(r"\b(file|image|mimes:|mimetypes:)\b", re.IGNORECASE)
    _AUTH_CONTEXT_HINTS = ("upload", "media", "attachment", "avatar", "document", "file")
    _VALIDATION_CONTEXT_MARKERS = (
        "function rules(",
        "public function rules(",
        "protected function rules(",
        "->validate(",
        "validator::make(",
        "validatewithbag(",
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
        text = content or ""
        low_path = str(file_path or "").replace("\\", "/").lower()
        if any(marker in low_path for marker in self._ALLOWLIST_PATH_MARKERS):
            return []

        require_upload_capability = bool(self.get_threshold("require_upload_capability", False))
        if require_upload_capability and not self._capability_enabled(facts, "file_upload_storage_heavy"):
            return []

        if not any(token in low_path for token in self._AUTH_CONTEXT_HINTS) and "file" not in text.lower():
            return []
        if not self._looks_like_validation_context(low_path, text):
            return []

        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        for match in self._UPLOAD_RULE.finditer(text):
            field = str(match.group("field") or "")
            rules_text = str(match.group("rules") or "")
            rules_low = rules_text.lower()
            if not self._UPLOAD_SIGNAL.search(rules_low):
                continue
            if self._has_explicit_max_size(rules_low):
                continue

            line = text.count("\n", 0, match.start()) + 1
            confidence = 0.8
            if confidence + 1e-9 < min_confidence:
                continue
            return [
                self.create_finding(
                    title="Upload validation appears to miss max size limit",
                    context=f"{file_path}:{line}:{field}",
                    file=file_path,
                    line_start=line,
                    description=(
                        f"Detected upload validation for `{field}` without explicit `max:` size constraint."
                    ),
                    why_it_matters=(
                        "Missing file size limits can enable payload abuse, storage exhaustion, and degraded application availability."
                    ),
                    suggested_fix=(
                        "Add explicit upload size limits (for example `max:2048` for 2MB) and align limits with server/webserver upload constraints."
                    ),
                    tags=["laravel", "security", "upload", "payload", "dos"],
                    confidence=confidence,
                    evidence_signals=[
                        f"field={field}",
                        "upload_rule_detected=true",
                        "size_limit_missing=true",
                    ],
                )
            ]
        return []

    def _looks_like_validation_context(self, low_path: str, text: str) -> bool:
        if any(marker in low_path for marker in ("/http/requests/", "/requests/")):
            return True
        text_low = text.lower()
        return any(marker in text_low for marker in self._VALIDATION_CONTEXT_MARKERS)

    def _has_explicit_max_size(self, rules_low: str) -> bool:
        normalized = str(rules_low or "").replace(" ", "")
        return "max:" in normalized or "->max(" in normalized

    def _capability_enabled(self, facts: Facts, key: str) -> bool:
        project_context = getattr(facts, "project_context", None)
        payload = None
        if project_context is not None:
            payload = (getattr(project_context, "capabilities", {}) or {}).get(key)
            if payload is None:
                payload = (getattr(project_context, "backend_capabilities", {}) or {}).get(key)
        return bool(isinstance(payload, dict) and payload.get("enabled"))
