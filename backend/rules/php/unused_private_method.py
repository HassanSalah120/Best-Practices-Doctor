"""
Unused Private Method Rule

Heuristic: flags private methods that are never called within the same class.

Notes:
- Tree-sitter facts are the source of truth; we only use derived index built from Facts.
- This is intentionally conservative (prefer false negatives over false positives).
"""

from __future__ import annotations

from analysis.call_graph_index import get_call_graph_index
from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class UnusedPrivateMethodRule(Rule):
    id = "unused-private-method"
    name = "Unused Private Method"
    description = "Detects private methods that appear to be unused within their class"
    category = Category.MAINTAINABILITY
    default_severity = Severity.LOW

    # Start conservative: Laravel-style OOP codebases where method calls are mostly explicit.
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        idx = get_call_graph_index(facts)

        # Map (file, class short name) -> class fqcn for fallback when class_fqcn is missing.
        fqcn_by_file_and_name: dict[tuple[str, str], str] = {}
        for c in facts.classes:
            if c.file_path and c.name and c.fqcn:
                fqcn_by_file_and_name[(c.file_path, c.name)] = c.fqcn

        classes_with_dynamic_dispatch: set[str] = set()
        for m in facts.methods:
            if m.name in {"__call", "__callStatic"}:
                cls = m.class_fqcn or fqcn_by_file_and_name.get((m.file_path, m.class_name), "")
                if cls:
                    classes_with_dynamic_dispatch.add(cls)

        findings: list[Finding] = []
        for m in facts.methods:
            if (m.visibility or "public") != "private":
                continue
            if not m.name or m.name.startswith("__"):
                continue

            cls = m.class_fqcn or fqcn_by_file_and_name.get((m.file_path, m.class_name), "")
            if not cls:
                # Last-resort fallback (less precise): group by short class name.
                cls = m.class_name

            # If a class uses __call/__callStatic, avoid unused-method claims.
            if cls in classes_with_dynamic_dispatch:
                continue

            called = idx.internal_called_method_names_by_class.get(cls, set())
            if m.name in called:
                continue

            findings.append(
                self.create_finding(
                    title="Unused private method",
                    context=m.method_fqn,
                    file=m.file_path,
                    line_start=m.line_start or 1,
                    line_end=m.line_end or None,
                    description=(
                        f"Private method `{m.method_fqn}` does not appear to be called within its class. "
                        "This may be dead code."
                    ),
                    why_it_matters=(
                        "Unused private methods add maintenance overhead, increase cognitive load, and can hide "
                        "stale logic. Removing dead code reduces risk and makes refactors safer."
                    ),
                    suggested_fix=(
                        "1. Confirm the method is truly unused (including dynamic call paths)\n"
                        "2. Remove the method if it's dead\n"
                        "3. If it should be used, add an explicit call site or refactor to make usage clear"
                    ),
                    tags=["dead_code", "maintainability"],
                    confidence=0.7,
                )
            )

        return findings

