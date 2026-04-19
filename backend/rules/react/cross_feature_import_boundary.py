"""
Cross Feature Import Boundary Rule

Flags deep cross-feature imports that bypass a feature's public API boundary.
"""

from __future__ import annotations

import posixpath
import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Category, Finding, FindingClassification, Severity
from rules.base import Rule


class CrossFeatureImportBoundaryRule(Rule):
    id = "cross-feature-import-boundary"
    name = "Cross-Feature Import Boundary Violation"
    description = "Detects deep imports across feature boundaries"
    category = Category.ARCHITECTURE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _ALLOWLIST_PATH_MARKERS = (".test.", ".spec.", "__tests__", ".stories.")
    _IMPORT_RE = re.compile(
        r"import\s+[^;]*?\s+from\s+['\"](?P<target>[^'\"]+)['\"]",
        re.IGNORECASE,
    )
    _FEATURE_PATH_RE = re.compile(r"(?:^|/)features/(?P<feature>[a-zA-Z0-9_-]+)(?:/(?P<rest>.*))?$", re.IGNORECASE)

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
        normalized_file = (file_path or "").replace("\\", "/")
        normalized_file_low = normalized_file.lower()
        if any(marker in normalized_file_low for marker in self._ALLOWLIST_PATH_MARKERS):
            return []

        source_feature, _ = self._feature_segments(normalized_file)
        if not source_feature:
            return []

        allow_entrypoint_import = bool(self.get_threshold("allow_entrypoint_import", True))
        max_findings_per_file = max(1, int(self.get_threshold("max_findings_per_file", 3)))
        findings: list[Finding] = []

        for match in self._IMPORT_RE.finditer(content or ""):
            if len(findings) >= max_findings_per_file:
                break
            import_target = str(match.group("target") or "").strip()
            resolved = self._resolve_import(normalized_file, import_target)
            target_feature, rest = self._feature_segments(resolved)
            if not target_feature:
                continue
            if target_feature == source_feature:
                continue
            if allow_entrypoint_import and self._is_feature_entrypoint(rest):
                continue

            line_number = (content or "").count("\n", 0, match.start()) + 1
            findings.append(
                self.create_finding(
                    title="Cross-feature deep import bypasses boundary",
                    context=f"{source_feature} -> {target_feature}",
                    file=file_path,
                    line_start=line_number,
                    description=(
                        f"File in feature `{source_feature}` imports deep path from feature `{target_feature}`: "
                        f"`{import_target}`."
                    ),
                    why_it_matters=(
                        "Deep cross-feature imports create tight coupling and make feature boundaries fragile. "
                        "Import through public entrypoints to keep architecture maintainable."
                    ),
                    suggested_fix=(
                        f"Expose required exports from `features/{target_feature}/index` (or the feature public API) "
                        "and import from that boundary instead of deep internal paths."
                    ),
                    confidence=0.86,
                    tags=["react", "architecture", "boundaries", "imports"],
                    evidence_signals=[
                        f"source_feature={source_feature}",
                        f"target_feature={target_feature}",
                        f"target={import_target}",
                    ],
                    metadata={
                        "decision_profile": {
                            "source_feature": source_feature,
                            "target_feature": target_feature,
                            "resolved_import": resolved,
                            "allow_entrypoint_import": allow_entrypoint_import,
                        }
                    },
                )
            )

        return findings

    def _resolve_import(self, importer_path: str, import_target: str) -> str:
        target = (import_target or "").strip().replace("\\", "/")
        if target.startswith("@/"):
            return target[2:]
        if target.startswith("src/"):
            return target
        if target.startswith("."):
            importer_dir = posixpath.dirname(importer_path)
            return posixpath.normpath(posixpath.join(importer_dir, target))
        return target

    def _feature_segments(self, path_value: str) -> tuple[str, str]:
        normalized = (path_value or "").replace("\\", "/").lstrip("./")
        match = self._FEATURE_PATH_RE.search(normalized)
        if not match:
            return "", ""
        feature = str(match.group("feature") or "")
        rest = str(match.group("rest") or "")
        return feature, rest

    def _is_feature_entrypoint(self, rest: str) -> bool:
        candidate = (rest or "").strip().strip("/")
        if not candidate:
            return True
        return candidate in {
            "index",
            "index.ts",
            "index.tsx",
            "index.js",
            "index.jsx",
            "public",
            "public/index",
            "public/index.ts",
            "public/index.tsx",
        }
