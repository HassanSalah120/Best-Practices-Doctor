"""
Prefer Imports Rule (AST-based)

Detects fully-qualified class name (FQCN) usage like `\\App\\Foo\\Bar` and suggests
adding a top-level `use App\\Foo\\Bar;` import and using the short class name.

This rule is AST-based and consumes FactsBuilder-extracted facts:
- Facts.use_imports
- Facts.fqcn_references
- Facts.php_namespaces

It MUST NOT read from disk or run regex parsing.
"""

from __future__ import annotations

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class PreferImportsRule(Rule):
    id = "prefer-imports"
    name = "Prefer imports instead of fully-qualified class names"
    description = "Suggests importing project classes with `use` instead of referencing FQCNs directly."
    category = Category.MAINTAINABILITY
    default_severity = Severity.LOW
    type = "ast"
    applicable_project_types: list[str] = []  # all

    def _get_root_namespaces(self) -> list[str]:
        raw = self.get_threshold("root_namespaces", ["App\\"])
        if isinstance(raw, str):
            raw = [raw]
        out: list[str] = []
        for ns in (raw or []):
            s = (str(ns) if ns is not None else "").strip()
            if not s:
                continue
            # Normalize: no leading "\"; ensure trailing "\" for prefix matching.
            s = s.lstrip("\\")
            if not s.endswith("\\"):
                s = s + "\\"
            out.append(s)
        return out or ["App\\"]

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        root_namespaces = self._get_root_namespaces()

        imports_by_file: dict[str, set[str]] = {}
        for imp in getattr(facts, "use_imports", []) or []:
            try:
                fp = imp.file_path
                fqcn = (imp.fqcn or "").lstrip("\\")
            except Exception:
                continue
            if not fp or not fqcn:
                continue
            imports_by_file.setdefault(fp, set()).add(fqcn)

        namespaces_by_file: dict[str, str] = getattr(facts, "php_namespaces", {}) or {}

        seen: set[tuple[str, str]] = set()  # (file, fqcn)
        for ref in getattr(facts, "fqcn_references", []) or []:
            file_path = getattr(ref, "file_path", "") or ""
            fqcn = (getattr(ref, "fqcn", "") or "").lstrip("\\")
            if not file_path or not fqcn:
                continue

            if not any(fqcn.startswith(ns) for ns in root_namespaces):
                continue

            # If imported (even with alias), don't flag (per rule spec).
            if fqcn in imports_by_file.get(file_path, set()):
                continue

            # Don't flag same-namespace references (they can be used without imports).
            file_ns = (namespaces_by_file.get(file_path) or "").strip().lstrip("\\").rstrip("\\")
            if file_ns:
                fqcn_ns = "\\".join(fqcn.split("\\")[:-1]).rstrip("\\")
                if fqcn_ns == file_ns:
                    continue

            key = (file_path, fqcn)
            if key in seen:
                continue
            seen.add(key)

            short = fqcn.split("\\")[-1]
            raw = getattr(ref, "raw", "") or ("\\" + fqcn)
            snippet = getattr(ref, "snippet", "") or raw

            before = snippet.strip()
            after_snippet = before.replace("\\" + fqcn, short)

            code_example = (
                "Before:\n"
                f"{before}\n\n"
                "After:\n"
                f"use {fqcn};\n"
                "...\n"
                f"{after_snippet}\n"
            )

            findings.append(
                self.create_finding(
                    title="Use import instead of fully-qualified class name",
                    file=file_path,
                    line_start=int(getattr(ref, "line_number", 1) or 1),
                    description=(
                        f"Class `{fqcn}` is referenced using a fully-qualified name. "
                        "Import it with `use` and reference the short class name."
                    ),
                    why_it_matters=(
                        "Fully-qualified class names in-line make code harder to read and refactor. "
                        "Using `use` imports follows PSR-12 conventions and keeps code concise."
                    ),
                    suggested_fix=(
                        f"1. Add `use {fqcn};` near the top of the file\n"
                        f"2. Replace `\\\\{fqcn}` with `{short}`\n"
                        "3. Keep imports sorted and remove unused imports"
                    ),
                    context=fqcn,
                    code_example=code_example,
                    tags=["imports", "fqcn", "psr12", "readability"],
                    confidence=0.9,
                )
            )

        return findings

