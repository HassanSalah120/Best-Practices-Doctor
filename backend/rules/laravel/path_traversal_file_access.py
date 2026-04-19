"""
Path Traversal File Access Rule

Detects request-derived filesystem paths flowing into file access sinks
without visible normalization/allowlist guards.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class PathTraversalFileAccessRule(Rule):
    id = "path-traversal-file-access"
    name = "Path Traversal File Access"
    description = "Detects request-derived file paths used in file access sinks without normalization"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".php"]

    _ALLOWLIST_PATH_MARKERS = ("/tests/", "/test/", "/vendor/", "/database/", "/storage/framework/views/")
    _REQUEST_ASSIGN = re.compile(
        r"\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\$request->(?:input|query|get|post|route)\s*\(|request\(\)\s*->(?:input|query|get|post|route)\s*\(|\$_(?:GET|POST|REQUEST)\s*\[)",
        re.IGNORECASE,
    )
    _DIRECT_REQUEST_TO_SINK = re.compile(
        r"(?:file_get_contents|fopen|readfile|unlink|scandir|file_exists|is_file|is_dir|copy|rename)\s*\(\s*(?:\$request->(?:input|query|get|post|route)\s*\(|request\(\)\s*->(?:input|query|get|post|route)\s*\(|\$_(?:GET|POST|REQUEST)\s*\[)",
        re.IGNORECASE,
    )
    _VAR_SINK = re.compile(
        r"(?:file_get_contents|fopen|readfile|unlink|scandir|file_exists|is_file|is_dir|copy|rename)\s*\(\s*\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)\b",
        re.IGNORECASE,
    )
    _STORAGE_SINK = re.compile(
        r"storage::(?:disk\s*\([^)]*\)\s*->\s*)?(?:get|put|exists|delete|path)\s*\(\s*\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)\b",
        re.IGNORECASE,
    )
    _SAFE_SIGNALS = (
        "realpath(",
        "basename(",
        "storage_path(",
        "public_path(",
        "str_starts_with(",
        "startswith(",
        "normalizepath",
        "cleanpath",
        "isSafePath".lower(),
        "allowed_paths",
        "allowlist",
        "whitelist",
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
        if "response()->download(" in text.lower() or "storage::download(" in text.lower():
            # Let the dedicated download rule own this path.
            return []

        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        findings: list[Finding] = []

        direct = self._DIRECT_REQUEST_TO_SINK.search(text)
        if direct:
            line = text.count("\n", 0, direct.start()) + 1
            confidence = 0.92
            if confidence + 1e-9 >= min_confidence:
                findings.append(
                    self.create_finding(
                        title="Request input reaches filesystem access sink",
                        context="direct-request-path-to-file-sink",
                        file=file_path,
                        line_start=line,
                        description=(
                            "Detected request-derived path used directly in a filesystem read/write API."
                        ),
                        why_it_matters=(
                            "Unsanitized user-controlled filesystem paths can enable directory traversal and unauthorized file access."
                        ),
                        suggested_fix=(
                            "Normalize and resolve the path against a trusted base directory, reject traversal segments (`..`), "
                            "and enforce an explicit allowlist before file operations."
                        ),
                        tags=["laravel", "security", "path-traversal", "file-access"],
                        confidence=confidence,
                        evidence_signals=["path_source=request_input", "sink=file_access_api", "sanitizer_signal=false"],
                    )
                )
            return findings

        request_vars: set[str] = set()
        for match in self._REQUEST_ASSIGN.finditer(text):
            request_vars.add(str(match.group("var") or "").strip())
        if not request_vars:
            return []

        for match, sink_name in self._iter_var_sinks(text):
            var_name = str(match.group("var") or "").strip()
            if not var_name or var_name not in request_vars:
                continue
            line = text.count("\n", 0, match.start()) + 1
            window = self._window(text, match.start(), before=26, after=14).lower()
            if any(signal in window for signal in self._SAFE_SIGNALS):
                continue

            confidence = 0.86
            if confidence + 1e-9 < min_confidence:
                continue
            findings.append(
                self.create_finding(
                    title="Potential path traversal via request-derived path variable",
                    context=f"path_var={var_name}",
                    file=file_path,
                    line_start=line,
                    description=(
                        f"Detected `${var_name}` (request-derived path) used in `{sink_name}` without visible path normalization."
                    ),
                    why_it_matters=(
                        "Path traversal can expose sensitive files and break tenant/user boundaries if arbitrary filesystem paths are accepted."
                    ),
                    suggested_fix=(
                        "Constrain file operations to a known storage root, validate resolved paths with `realpath`, and reject values "
                        "outside the allowlisted directory."
                    ),
                    tags=["laravel", "security", "path-traversal", "file-access"],
                    confidence=confidence,
                    evidence_signals=[
                        f"path_var={var_name}",
                        f"sink={sink_name}",
                        "path_source=request_input",
                        "sanitizer_signal=false",
                    ],
                )
            )
            break

        return findings

    def _iter_var_sinks(self, text: str) -> list[tuple[re.Match[str], str]]:
        out: list[tuple[re.Match[str], str]] = []
        for match in self._VAR_SINK.finditer(text):
            sink_text = text[match.start():match.end()].split("(", 1)[0].strip().lower()
            out.append((match, sink_text))
        for match in self._STORAGE_SINK.finditer(text):
            out.append((match, "storage"))
        out.sort(key=lambda item: item[0].start())
        return out

    def _window(self, text: str, start_idx: int, before: int = 24, after: int = 12) -> str:
        lines = text.splitlines()
        line = text.count("\n", 0, start_idx) + 1
        start_line = max(0, line - before - 1)
        end_line = min(len(lines), line + after)
        return "\n".join(lines[start_line:end_line])

