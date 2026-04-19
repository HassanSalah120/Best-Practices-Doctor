"""
Upload MIME/Extension Mismatch Rule

Detects upload validation that relies on extension checks while code also trusts
original filename extensions, which can lead to MIME/extension mismatch abuse.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class UploadMimeExtensionMismatchRule(Rule):
    id = "upload-mime-extension-mismatch"
    name = "Upload MIME/Extension Mismatch Risk"
    description = "Detects upload flows that trust client extensions without MIME hardening"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".php"]

    _ALLOWLIST_PATH_MARKERS = ("/tests/", "/test/", "/vendor/")
    _MIMES_RULE = re.compile(r"mimes\s*:[^'\"|\],\n)]+", re.IGNORECASE)
    _MIMETYPES_RULE = re.compile(r"mimetypes\s*:[^'\"|\],\n)]+", re.IGNORECASE)
    _EXTENSION_USAGE = re.compile(
        r"(?:getClientOriginalExtension\s*\(|pathinfo\s*\([^)]*PATHINFO_EXTENSION|clientoriginalname)",
        re.IGNORECASE,
    )
    _MIME_RUNTIME_CHECK = re.compile(r"(?:getMimeType\s*\(|finfo_|mime_content_type\s*\()", re.IGNORECASE)

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

        has_mimes = bool(self._MIMES_RULE.search(text))
        has_mimetypes = bool(self._MIMETYPES_RULE.search(text))
        has_extension_usage = bool(self._EXTENSION_USAGE.search(text))
        has_runtime_mime_check = bool(self._MIME_RUNTIME_CHECK.search(text))
        if not (has_mimes and has_extension_usage):
            return []
        if has_mimetypes or has_runtime_mime_check:
            return []

        line = text.count("\n", 0, self._EXTENSION_USAGE.search(text).start()) + 1 if self._EXTENSION_USAGE.search(text) else 1
        confidence = 0.86
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        if confidence + 1e-9 < min_confidence:
            return []

        return [
            self.create_finding(
                title="Upload flow may trust extension more than MIME type",
                context=f"{file_path}:{line}:upload-mime-extension",
                file=file_path,
                line_start=line,
                description=(
                    "Detected `mimes:` validation with direct original-extension usage but no explicit MIME-type hardening."
                ),
                why_it_matters=(
                    "Client-controlled extensions can be spoofed. MIME/extension mismatch can allow unexpected payload types."
                ),
                suggested_fix=(
                    "Prefer strict MIME validation (`mimetypes:` and/or runtime MIME inspection), avoid security decisions based on "
                    "`getClientOriginalExtension()`, and store uploads with generated filenames."
                ),
                tags=["laravel", "security", "upload", "mime", "extension"],
                confidence=confidence,
                evidence_signals=[
                    f"has_mimes={int(has_mimes)}",
                    f"has_mimetypes={int(has_mimetypes)}",
                    f"has_extension_usage={int(has_extension_usage)}",
                    f"runtime_mime_check={int(has_runtime_mime_check)}",
                ],
            )
        ]

    def _capability_enabled(self, facts: Facts, key: str) -> bool:
        project_context = getattr(facts, "project_context", None)
        payload = None
        if project_context is not None:
            payload = (getattr(project_context, "capabilities", {}) or {}).get(key)
            if payload is None:
                payload = (getattr(project_context, "backend_capabilities", {}) or {}).get(key)
        return bool(isinstance(payload, dict) and payload.get("enabled"))

