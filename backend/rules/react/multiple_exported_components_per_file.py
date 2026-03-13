"""
Multiple Exported Components Per File Rule

Detects files exporting more than one top-level React component.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class MultipleExportedComponentsPerFileRule(Rule):
    id = "multiple-exported-react-components"
    name = "Multiple Exported React Components"
    description = "Detects files exporting multiple top-level React components"
    category = Category.MAINTAINABILITY
    default_severity = Severity.LOW
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _EXPORT_FN = re.compile(r"^\s*export\s+(?:default\s+)?function\s+([A-Z][A-Za-z0-9_]*)\s*\(", re.MULTILINE)
    _EXPORT_CONST = re.compile(
        r"^\s*export\s+const\s+([A-Z][A-Za-z0-9_]*)\s*(?::[^=]+)?=\s*(?:\(|async\b)",
        re.MULTILINE,
    )
    _EXPORT_DEFAULT = re.compile(r"^\s*export\s+default\s+(?:function\s+)?([A-Z][A-Za-z0-9_]*)?", re.MULTILINE)
    _TYPE_EXPORT = re.compile(r"^\s*export\s+type\s+\{?\s*([A-Z][A-Za-z0-9_]*)?", re.MULTILINE)
    _VARIANT_TOKENS = (
        "Single",
        "Multi",
        "Default",
        "Base",
        "Primary",
        "Secondary",
        "Desktop",
        "Mobile",
        "Compact",
        "Expanded",
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
        norm = (file_path or "").replace("\\", "/").lower()
        if any(x in norm for x in [".test.", ".spec.", "__tests__", ".stories."]):
            return []
        if ".components." in norm:
            return []

        # Get all exported names
        all_exported = set(self._EXPORT_FN.findall(content or ""))
        all_exported.update(self._EXPORT_CONST.findall(content or ""))
        
        # Get default exports (only one allowed per file)
        default_exports = self._EXPORT_DEFAULT.findall(content or "")
        default_exports = [e for e in default_exports if e]  # Filter out empty matches
        
        # Get type exports (these don't count as components)
        type_exports = self._TYPE_EXPORT.findall(content or "")
        
        # Remove type exports from component list
        for type_name in type_exports:
            if type_name in all_exported:
                all_exported.discard(type_name)
        
        # Check if file has more than one default export (this is the real problem)
        if len(default_exports) > 1:
            line = 1
            return [
                self.create_finding(
                    title="File exports multiple default React components",
                    context=f"{file_path}:exports",
                    file=file_path,
                    line_start=line,
                    description=(
                        f"Detected {len(default_exports)} default exported React components in one file. "
                        f"Only one default export is allowed per file."
                    ),
                    why_it_matters=(
                        "Multiple default exports in a single file break module boundaries and make "
                        "navigation and code organization confusing."
                    ),
                    suggested_fix=(
                        "Split this file into separate component files, one default export per file."
                    ),
                    tags=["react", "structure", "components", "module-boundaries"],
                    confidence=0.9,
                    evidence_signals=[f"default_exports={len(default_exports)}"],
                )
            ]
        
        if len(all_exported) <= 1:
            return []
        
        names = sorted(all_exported)
        base_names = [self._variant_base_name(n) for n in names]
        
        # If all components share a common base name, they're likely variants
        if len(set(base_names)) == 1:
            return []
        if self._share_file_prefix(file_path, names):
            return []

        line = 1
        return [
            self.create_finding(
                title="File exports multiple unrelated React components",
                context=f"{file_path}:exports",
                file=file_path,
                line_start=line,
                description=(
                    f"Detected {len(all_exported)} exported React components in one file: {', '.join(names[:4])}. "
                    f"These appear to be unrelated components."
                ),
                why_it_matters=(
                    "Exporting multiple unrelated components from the same file blurs file ownership "
                    "and makes module navigation harder as the frontend grows."
                ),
                suggested_fix=(
                    "Prefer one exported component per file for leaf UI modules. Keep shared view pieces in their "
                    "own component files and re-export them from an index file if needed."
                ),
                tags=["react", "structure", "components", "module-boundaries"],
                confidence=0.78,
                evidence_signals=[f"exported_components={len(all_exported)}"],
            )
        ]

    @classmethod
    def _variant_base_name(cls, name: str) -> str:
        normalized = name
        for token in cls._VARIANT_TOKENS:
            normalized = normalized.replace(token, "")
        return normalized.lower()

    @staticmethod
    def _split_tokens(name: str) -> list[str]:
        text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
        return [part for part in re.split(r"[^A-Za-z0-9]+", text) if part]

    @classmethod
    def _share_file_prefix(cls, file_path: str, names: list[str]) -> bool:
        stem = (file_path or "").replace("\\", "/").split("/")[-1].split(".")[0]
        stem_prefix = "".join(cls._split_tokens(stem)).lower()
        if len(names) == 2 and any(name.lower() == stem_prefix for name in names):
            return True
        if stem_prefix and all(name.lower().startswith(stem_prefix) for name in names):
            return True

        tokenized = [cls._split_tokens(name) for name in names]
        shared_prefix: list[str] = []
        for parts in zip(*tokenized):
            if len(set(parts)) != 1:
                break
            shared_prefix.append(parts[0])

        prefix_text = "".join(shared_prefix).lower()
        return len(prefix_text) >= 4
