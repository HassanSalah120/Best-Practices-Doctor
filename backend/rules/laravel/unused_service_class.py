"""
Unused Service Class Rule

Heuristic: flags classes under app/Services that appear to be never referenced.

References include (best-effort, AST-derived):
- constructor/method DI type hints
- `new ClassName` instantiations
- `ClassName::...` occurrences inside call expressions (including `ClassName::class`)

This is intentionally conservative. Prefer false negatives over false positives.
"""

from __future__ import annotations

import re

from analysis.call_graph_index import get_call_graph_index
from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class UnusedServiceClassRule(Rule):
    id = "unused-service-class"
    name = "Unused Service Class"
    description = "Detects service classes in app/Services that appear to be unused"
    category = Category.MAINTAINABILITY
    default_severity = Severity.LOW

    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]
    _CLASS_CONST_REF = re.compile(r"\\?(?P<class>[A-Za-z_][A-Za-z0-9_\\\\]*)::class", re.IGNORECASE)

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        idx = get_call_graph_index(facts)

        referenced_fqcns = {str(x).strip().lstrip("\\") for x in (idx.referenced_class_fqcns or set()) if x}
        referenced_basenames = set(idx.referenced_class_basenames or set())
        implemented_interfaces_by_service: dict[str, set[str]] = {}
        provider_binding_basenames: set[str] = set()
        provider_binding_fqcns: set[str] = set()
        # Some references are stored as short names in `referenced_class_fqcns`; treat them as basenames too.
        for x in referenced_fqcns:
            if "\\" not in x:
                referenced_basenames.add(x)

        # Include raw FQCN references (outside method call-sites), commonly used in container/provider maps.
        for ref in getattr(facts, "fqcn_references", []) or []:
            fqcn = str(getattr(ref, "fqcn", "") or "").strip().lstrip("\\")
            if not fqcn:
                continue
            referenced_fqcns.add(fqcn)
            referenced_basenames.add(fqcn.split("\\")[-1])

        for ref in getattr(facts, "class_const_accesses", []) or []:
            expression = str(getattr(ref, "expression", "") or "")
            file_path = str(getattr(ref, "file_path", "") or "").replace("\\", "/").lower()
            for match in self._CLASS_CONST_REF.finditer(expression):
                class_name = str(match.groupdict().get("class") or "").strip().lstrip("\\")
                if not class_name:
                    continue
                referenced_fqcns.add(class_name)
                referenced_basenames.add(class_name.split("\\")[-1])
                if "/providers/" in file_path:
                    provider_binding_fqcns.add(class_name)
                    provider_binding_basenames.add(class_name.split("\\")[-1])

        for c in facts.classes:
            fqcn = str(c.fqcn or "").lstrip("\\")
            if not fqcn:
                continue
            interfaces = {
                str(interface or "").strip().lstrip("\\")
                for interface in (c.implements or [])
                if str(interface or "").strip()
            }
            if interfaces:
                implemented_interfaces_by_service[fqcn] = interfaces

        findings: list[Finding] = []
        for c in facts.classes:
            p = (c.file_path or "").replace("\\", "/")
            pl = p.lower()
            if not pl.startswith("app/services/"):
                continue

            fqcn = (c.fqcn or "").lstrip("\\")
            if not fqcn:
                continue

            # Skip abstract classes - they are used via inheritance
            if getattr(c, "is_abstract", False):
                continue

            if fqcn in referenced_fqcns:
                continue
            if c.name in referenced_basenames:
                continue
            if fqcn in provider_binding_fqcns or c.name in provider_binding_basenames:
                continue
            if self._is_referenced_via_interface(fqcn, implemented_interfaces_by_service, referenced_fqcns, referenced_basenames):
                continue

            findings.append(
                self.create_finding(
                    title="Unused service class",
                    context=fqcn,
                    file=c.file_path,
                    line_start=c.line_start or 1,
                    line_end=c.line_end or None,
                    description=(
                        f"Service class `{fqcn}` (in `{p}`) does not appear to be referenced "
                        "via DI, instantiation, or static usage."
                    ),
                    why_it_matters=(
                        "Unused services are dead code: they increase maintenance cost and can confuse readers about "
                        "which workflows actually exist. Removing them simplifies the architecture."
                    ),
                    suggested_fix=(
                        "1. Confirm the service is unused (search for type hints, `new`, and `::class` references)\n"
                        "2. Remove the class if it's dead\n"
                        "3. If it should be used, wire it via DI (constructor injection) or an explicit call site"
                    ),
                    tags=["dead_code", "maintainability", "laravel"],
                    confidence=0.76,
                )
            )

        return findings

    @staticmethod
    def _is_referenced_via_interface(
        fqcn: str,
        implemented_interfaces_by_service: dict[str, set[str]],
        referenced_fqcns: set[str],
        referenced_basenames: set[str],
    ) -> bool:
        interfaces = implemented_interfaces_by_service.get(fqcn, set())
        if not interfaces:
            return False
        for interface in interfaces:
            if interface in referenced_fqcns:
                return True
            if interface.split("\\")[-1] in referenced_basenames:
                return True
        return False
