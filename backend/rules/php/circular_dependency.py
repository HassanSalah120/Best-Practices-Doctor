"""
Circular Dependency Rule

Detects dependency cycles between App\\* classes using an AST-derived dependency graph.
"""

from __future__ import annotations

import re

from analysis.dependency_graph import get_dependency_graph, strongly_connected_components
from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule

_RELATION_METHOD_RE = re.compile(
    r"\b(?:belongsTo|hasOne|hasMany|belongsToMany|morphTo|morphOne|morphMany|morphToMany|morphedByMany|hasOneThrough|hasManyThrough)\s*\(",
    re.IGNORECASE,
)
_SCOPED_CLASS_REF = re.compile(r"\\?(?P<class>[A-Za-z_][A-Za-z0-9_\\\\]*)::")


class CircularDependencyRule(Rule):
    id = "circular-dependency"
    name = "Circular Dependency"
    description = "Detects circular dependencies between classes (cycles in the dependency graph)"
    category = Category.ARCHITECTURE
    default_severity = Severity.HIGH
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]
    _ABSTRACTION_SUFFIXES = ("Interface", "Contract", "Handler", "Gateway")

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        g = get_dependency_graph(facts)

        classes_by_fqcn = {c.fqcn.lstrip("\\"): c for c in facts.classes if c.fqcn}
        fqcn_by_basename = self._fqcn_by_basename(classes_by_fqcn)
        model_fqcns = {
            (m.fqcn or "").lstrip("\\")
            for m in [*facts.models, *facts.classes]
            if (m.fqcn or "").lstrip("\\").startswith("App\\Models\\")
        }
        relation_edges = self._collect_model_relation_edges(facts, classes_by_fqcn, fqcn_by_basename, model_fqcns)
        app_nodes = {fqcn for fqcn in g.nodes if fqcn.startswith("App\\")}
        if not app_nodes:
            return []

        # Subgraph restricted to App\\* classes for SCC detection.
        outgoing: dict[str, set[str]] = {}
        for n in app_nodes:
            outgoing[n] = {d for d in g.outgoing.get(n, set()) if d in app_nodes}

        comps = strongly_connected_components(outgoing)

        findings: list[Finding] = []
        for comp in comps:
            if len(comp) <= 1:
                continue

            members = sorted(set(comp))
            cycle_edges = {
                (src, dst)
                for src in members
                for dst in g.outgoing.get(src, set())
                if dst in members
            }
            if self._is_model_relation_cycle(members, cycle_edges, model_fqcns, relation_edges):
                continue
            if self._is_abstraction_only_cycle(members, classes_by_fqcn):
                continue
            ctx = "|".join(members)
            first = members[0]
            first_file = classes_by_fqcn.get(first).file_path if first in classes_by_fqcn else ""
            related_files = [classes_by_fqcn[c].file_path for c in members if c in classes_by_fqcn and classes_by_fqcn[c].file_path]

            findings.append(
                self.create_finding(
                    title="Circular dependency detected",
                    context=ctx,
                    file=first_file or (related_files[0] if related_files else ""),
                    line_start=classes_by_fqcn.get(first).line_start if first in classes_by_fqcn else 1,
                    description=(
                        "A dependency cycle exists between application classes. "
                        "Graph evidence (classes in the cycle):\n"
                        + "\n".join(f"- {c}" for c in members)
                    ),
                    why_it_matters=(
                        "Cycles increase coupling and make the codebase harder to change safely. "
                        "They complicate testing, hinder modularization, and often indicate missing abstractions "
                        "or misplaced responsibilities."
                    ),
                    suggested_fix=(
                        "1. Break the cycle by depending on an interface (inverting one edge)\n"
                        "2. Extract shared logic into a third component used by both sides\n"
                        "3. Introduce events/queues to decouple runtime collaboration\n"
                        "4. Re-check boundaries: services should orchestrate; actions should be small steps"
                    ),
                    related_files=sorted(set(related_files)),
                    related_methods=members,  # show cycle members as evidence
                    tags=["architecture", "coupling", "cycles"],
                    confidence=0.7,
                )
            )

        return findings

    @staticmethod
    def _fqcn_by_basename(classes_by_fqcn: dict[str, object]) -> dict[str, str]:
        out: dict[str, str] = {}
        seen_multi: set[str] = set()
        for fqcn in classes_by_fqcn.keys():
            base = fqcn.split("\\")[-1]
            if base in seen_multi:
                continue
            if base in out:
                out.pop(base, None)
                seen_multi.add(base)
                continue
            out[base] = fqcn
        return out

    @staticmethod
    def _resolve_class_ref(raw: str, classes_by_fqcn: dict[str, object], fqcn_by_basename: dict[str, str]) -> str | None:
        ref = str(raw or "").strip().lstrip("\\")
        if not ref:
            return None
        if ref in classes_by_fqcn:
            return ref
        if "\\" in ref:
            return None
        return fqcn_by_basename.get(ref)

    def _collect_model_relation_edges(
        self,
        facts: Facts,
        classes_by_fqcn: dict[str, object],
        fqcn_by_basename: dict[str, str],
        model_fqcns: set[str],
    ) -> set[tuple[str, str]]:
        edges: set[tuple[str, str]] = set()
        for method in facts.methods:
            owner = (method.class_fqcn or "").lstrip("\\")
            if owner not in model_fqcns:
                continue
            for call in method.call_sites or []:
                text = str(call or "")
                if not _RELATION_METHOD_RE.search(text):
                    continue
                for match in _SCOPED_CLASS_REF.finditer(text):
                    dst = self._resolve_class_ref(match.group("class") or "", classes_by_fqcn, fqcn_by_basename)
                    if dst and dst in model_fqcns and dst != owner:
                        edges.add((owner, dst))
        return edges

    @staticmethod
    def _is_model_relation_cycle(
        members: list[str],
        cycle_edges: set[tuple[str, str]],
        model_fqcns: set[str],
        relation_edges: set[tuple[str, str]],
    ) -> bool:
        if len(members) < 2:
            return False
        if not cycle_edges:
            return False
        if any(member not in model_fqcns for member in members):
            return False
        return cycle_edges.issubset(relation_edges)

    def _is_abstraction_only_cycle(self, members: list[str], classes_by_fqcn: dict[str, object]) -> bool:
        if len(members) < 2:
            return False

        descriptors: list[str] = []
        for member in members:
            cls = classes_by_fqcn.get(member)
            if not cls:
                return False
            descriptors.append(str(getattr(cls, "name", "") or member.split("\\")[-1]))

        return all(
            name.endswith(self._ABSTRACTION_SUFFIXES)
            or name.startswith(("Abstract", "Base"))
            for name in descriptors
        )
