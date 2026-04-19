"""
Archive Upload Zip Slip Risk Rule

Detects `ZipArchive::extractTo` usage without visible entry-path validation.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class ArchiveUploadZipSlipRiskRule(Rule):
    id = "archive-upload-zip-slip-risk"
    name = "Archive Upload Zip Slip Risk"
    description = "Detects ZipArchive extraction without traversal-safe entry validation"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".php"]

    _ALLOWLIST_PATH_MARKERS = ("/tests/", "/test/", "/vendor/")
    _EXTRACT_TO = re.compile(r"->\s*extractTo\s*\(", re.IGNORECASE)
    _ZIPARCHIVE = re.compile(r"ziparchive", re.IGNORECASE)
    _SAFE_SIGNALS = (
        "realpath(",
        "normalizepath",
        "cleanpath",
        "str_starts_with(",
        "startswith(",
        "getnameindex(",
        "contains('..'",
        "contains(\"..\"",
        "../",
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

        if not self._ZIPARCHIVE.search(text):
            return []

        match = self._EXTRACT_TO.search(text)
        if not match:
            return []

        window = self._window(text, match.start(), before=36, after=30).lower()
        if any(signal in window for signal in self._SAFE_SIGNALS):
            return []

        line = text.count("\n", 0, match.start()) + 1
        confidence = 0.9
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        if confidence + 1e-9 < min_confidence:
            return []

        return [
            self.create_finding(
                title="Archive extraction may be vulnerable to Zip Slip",
                context=f"{file_path}:{line}:zip-extract",
                file=file_path,
                line_start=line,
                description=(
                    "Detected `ZipArchive::extractTo(...)` without visible entry path normalization/traversal checks."
                ),
                why_it_matters=(
                    "Zip Slip can write files outside intended directories, potentially leading to arbitrary file overwrite or code execution."
                ),
                suggested_fix=(
                    "Iterate archive entries, normalize each path, reject `..` traversal, and enforce extraction root boundaries before writing files."
                ),
                tags=["laravel", "security", "upload", "archive", "zip-slip"],
                confidence=confidence,
                evidence_signals=[
                    "ziparchive_extract=true",
                    "path_normalization_missing=true",
                ],
            )
        ]

    def _window(self, text: str, start_idx: int, before: int = 24, after: int = 12) -> str:
        lines = text.splitlines()
        line = text.count("\n", 0, start_idx) + 1
        start_line = max(0, line - before - 1)
        end_line = min(len(lines), line + after)
        return "\n".join(lines[start_line:end_line])

    def _capability_enabled(self, facts: Facts, key: str) -> bool:
        project_context = getattr(facts, "project_context", None)
        payload = None
        if project_context is not None:
            payload = (getattr(project_context, "capabilities", {}) or {}).get(key)
            if payload is None:
                payload = (getattr(project_context, "backend_capabilities", {}) or {}).get(key)
        return bool(isinstance(payload, dict) and payload.get("enabled"))

