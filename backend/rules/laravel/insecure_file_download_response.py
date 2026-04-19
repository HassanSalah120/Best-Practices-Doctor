"""
Insecure File Download Response Rule

Detects download/file responses that use request-derived paths without
visible authorization and path safety guards.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class InsecureFileDownloadResponseRule(Rule):
    id = "insecure-file-download-response"
    name = "Insecure File Download Response"
    description = "Detects file download responses built from untrusted path input without guards"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".php"]

    _ALLOWLIST_PATH_MARKERS = ("/tests/", "/test/", "/vendor/")
    _REQUEST_ASSIGN = re.compile(
        r"\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\$request->(?:input|query|get|post|route)\s*\(|request\(\)\s*->(?:input|query|get|post|route)\s*\(|\$_(?:GET|POST|REQUEST)\s*\[)",
        re.IGNORECASE,
    )
    _DOWNLOAD_VAR = re.compile(
        r"(?:response\s*\(\s*\)\s*->\s*(?:download|file)|storage::download)\s*\(\s*\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)\b",
        re.IGNORECASE,
    )
    _DOWNLOAD_DIRECT = re.compile(
        r"(?:response\s*\(\s*\)\s*->\s*(?:download|file)|storage::download)\s*\(\s*(?:\$request->(?:input|query|get|post|route)\s*\(|request\(\)\s*->(?:input|query|get|post|route)\s*\()",
        re.IGNORECASE,
    )
    _PATH_SAFETY_SIGNALS = (
        "realpath(",
        "basename(",
        "storage_path(",
        "public_path(",
        "str_starts_with(",
        "startswith(",
        "allowlist",
        "whitelist",
        "safePath".lower(),
    )
    _AUTHZ_SIGNALS = (
        "authorize(",
        "gate::",
        "policy(",
        "->can(",
        "->cannot(",
        "where('user_id'",
        "where(\"user_id\"",
        "where('owner_id'",
        "where(\"owner_id\"",
        "where('tenant_id'",
        "where(\"tenant_id\"",
        "where('clinic_id'",
        "where(\"clinic_id\"",
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
        if "download(" not in text.lower() and "->file(" not in text.lower():
            return []

        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        require_auth_or_ownership_guard = bool(self.get_threshold("require_auth_or_ownership_guard", True))

        direct = self._DOWNLOAD_DIRECT.search(text)
        if direct:
            line = text.count("\n", 0, direct.start()) + 1
            confidence = 0.93
            if confidence + 1e-9 >= min_confidence:
                return [
                    self.create_finding(
                        title="Download response uses request input directly",
                        context="direct-request-input-download",
                        file=file_path,
                        line_start=line,
                        description=(
                            "Detected a download/file response where the file path is read directly from request input."
                        ),
                        why_it_matters=(
                            "Untrusted download paths can expose arbitrary files (IDOR/path traversal), including sensitive data."
                        ),
                        suggested_fix=(
                            "Resolve files from trusted IDs (not raw paths), enforce authorization/ownership checks, and normalize "
                            "paths against an allowlisted storage root before download."
                        ),
                        tags=["laravel", "security", "download", "idor", "path-traversal"],
                        confidence=confidence,
                        evidence_signals=["download_source=request_input", "path_validation_missing=true"],
                    )
                ]
            return []

        request_vars = {str(match.group("var") or "").strip() for match in self._REQUEST_ASSIGN.finditer(text)}
        if not request_vars:
            return []

        findings: list[Finding] = []
        for sink in self._DOWNLOAD_VAR.finditer(text):
            var_name = str(sink.group("var") or "").strip()
            if not var_name or var_name not in request_vars:
                continue
            window = self._window(text, sink.start(), before=28, after=14).lower()
            has_path_guard = any(sig in window for sig in self._PATH_SAFETY_SIGNALS)
            has_auth_guard = any(sig in window for sig in self._AUTHZ_SIGNALS)
            if has_path_guard and (has_auth_guard or not require_auth_or_ownership_guard):
                continue

            line = text.count("\n", 0, sink.start()) + 1
            confidence = 0.86 if has_auth_guard else 0.9
            if confidence + 1e-9 < min_confidence:
                continue
            findings.append(
                self.create_finding(
                    title="Potential insecure file download path handling",
                    context=f"download_var={var_name}",
                    file=file_path,
                    line_start=line,
                    description=(
                        f"Detected file download response using request-derived `${var_name}` without complete safety checks."
                    ),
                    why_it_matters=(
                        "Download endpoints are common abuse targets for account hijack and data exfiltration when path/ownership checks are incomplete."
                    ),
                    suggested_fix=(
                        "Use opaque file identifiers, verify resource ownership/authorization, and enforce normalized storage-root constraints "
                        "before returning `download()` responses."
                    ),
                    tags=["laravel", "security", "download", "idor", "authorization"],
                    confidence=confidence,
                    evidence_signals=[
                        f"download_var={var_name}",
                        "download_source=request_input",
                        f"path_guard={int(has_path_guard)}",
                        f"auth_guard={int(has_auth_guard)}",
                    ],
                )
            )
            break

        return findings

    def _window(self, text: str, start_idx: int, before: int = 24, after: int = 12) -> str:
        lines = text.splitlines()
        line = text.count("\n", 0, start_idx) + 1
        start_line = max(0, line - before - 1)
        end_line = min(len(lines), line + after)
        return "\n".join(lines[start_line:end_line])

