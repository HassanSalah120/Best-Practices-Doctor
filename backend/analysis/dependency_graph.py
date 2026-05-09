"""
Dependency Graph (Derived)

Builds a lightweight class dependency graph from existing Tree-sitter Facts.

Nodes: classes (FQCN)
Edges (best-effort, conservative):
- extends / implements (when resolvable to another known class)
- constructor DI type hints
- `new ClassName` instantiation
- static references `ClassName::...` (including `ClassName::class`)

Notes:
- Tree-sitter facts remain the source of truth for structure.
- This graph is derived, cached on Facts, and not serialized.
- We prefer false negatives over false positives (skip ambiguous resolutions).
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re

from schemas.facts import Facts, ClassInfo, MethodInfo


_SCOPED_CLASS_REF = re.compile(r"\\?(?P<class>[A-Za-z_][A-Za-z0-9_\\\\]*)::")


def _base_name(type_or_fqcn: str) -> str:
    s = (type_or_fqcn or "").strip().lstrip("\\")
    if not s:
        return ""
    return s.split("\\")[-1]


def _parse_param_type(raw: str) -> str | None:
    """Best-effort parse of a PHP parameter type from a raw parameter text."""
    if not raw:
        return None

    s = str(raw).strip()
    s = re.sub(r"^\s*(?:public|protected|private)\s+", "", s)
    s = re.sub(r"^\s*readonly\s+", "", s)

    m = re.match(r"^(?P<type>[^\s$]+)\s+(?P<var>\$\w+)\b", s)
    if not m:
        return None

    t = (m.group("type") or "").strip()
    if not t:
        return None

    t = t.lstrip("?")
    if "|" in t:
        parts = [p for p in t.split("|") if p and p.lower() != "null"]
        if not parts:
            return None
        t = parts[0].lstrip("?")

    t = t.strip().lstrip("\\")
    if not t:
        return None

    builtins = {
        "int",
        "string",
        "bool",
        "float",
        "array",
        "mixed",
        "callable",
        "iterable",
        "object",
        "void",
        "never",
        "self",
        "static",
        "parent",
    }
    if t.lower() in builtins:
        return None

    return t


def _normalize_type_name(t: str) -> str:
    return (t or "").strip().lstrip("\\")


def _is_app_fqcn(fqcn: str) -> bool:
    s = (fqcn or "").lstrip("\\")
    return s.startswith("App\\")


@dataclass
class DependencyGraph:
    nodes: set[str] = field(default_factory=set)
    outgoing: dict[str, set[str]] = field(default_factory=dict)

    def add_node(self, n: str) -> None:
        if not n:
            return
        self.nodes.add(n)
        self.outgoing.setdefault(n, set())

    def add_edge(self, src: str, dst: str) -> None:
        if not src or not dst:
            return
        if src == dst:
            return
        self.add_node(src)
        self.add_node(dst)
        self.outgoing[src].add(dst)

    def out_degree(self, n: str) -> int:
        return len(self.outgoing.get(n, set()))


def _build_resolution_maps(classes: list[ClassInfo]) -> tuple[dict[str, ClassInfo], dict[str, set[str]]]:
    by_fqcn: dict[str, ClassInfo] = {}
    by_basename: dict[str, set[str]] = {}
    for c in classes:
        fqcn = (c.fqcn or "").lstrip("\\")
        if not fqcn:
            continue
        by_fqcn[fqcn] = c
        bn = _base_name(fqcn)
        if bn:
            by_basename.setdefault(bn, set()).add(fqcn)
    return by_fqcn, by_basename


def _resolve_to_known_fqcn(
    raw: str,
    classes_by_fqcn: dict[str, ClassInfo],
    fqcns_by_basename: dict[str, set[str]],
) -> str | None:
    t = _normalize_type_name(raw)
    if not t:
        return None

    # Exact match
    if t in classes_by_fqcn:
        return t

    # If it's already a namespaced string, but not known, we keep it unknown.
    if "\\" in t:
        return None

    # Unqualified basename: resolve only if unique.
    cands = fqcns_by_basename.get(t, set())
    if len(cands) == 1:
        return next(iter(cands))
    return None


def build_dependency_graph(facts: Facts) -> DependencyGraph:
    classes_by_fqcn, fqcns_by_basename = _build_resolution_maps(facts.classes)
    g = DependencyGraph()

    # Nodes: known classes only.
    for fqcn in classes_by_fqcn.keys():
        g.add_node(fqcn)

    # Edges: extends/implements
    for c in facts.classes:
        src = (c.fqcn or "").lstrip("\\")
        if not src:
            continue
        if c.extends:
            dst = _resolve_to_known_fqcn(c.extends, classes_by_fqcn, fqcns_by_basename)
            if dst:
                g.add_edge(src, dst)
        for i in c.implements or []:
            dst = _resolve_to_known_fqcn(i, classes_by_fqcn, fqcns_by_basename)
            if dst:
                g.add_edge(src, dst)

    # Edges: from methods (DI, new, static refs)
    for m in facts.methods:
        owner = (m.class_fqcn or "").lstrip("\\")
        if not owner:
            continue

        # constructor DI
        if m.name == "__construct":
            for p in m.parameters or []:
                t = _parse_param_type(p)
                if not t:
                    continue
                dst = _resolve_to_known_fqcn(t, classes_by_fqcn, fqcns_by_basename)
                if dst:
                    g.add_edge(owner, dst)

        # new ClassName
        for inst in m.instantiations or []:
            t = _normalize_type_name(str(inst))
            if not t:
                continue
            dst = _resolve_to_known_fqcn(t, classes_by_fqcn, fqcns_by_basename)
            if dst:
                g.add_edge(owner, dst)

        # ClassName::...
        for cs in m.call_sites or []:
            call = str(cs)
            for rm in _SCOPED_CLASS_REF.finditer(call):
                c_name = _normalize_type_name(rm.group("class") or "")
                if not c_name:
                    continue
                if c_name.lower() in {"self", "static", "parent"}:
                    continue
                dst = _resolve_to_known_fqcn(c_name, classes_by_fqcn, fqcns_by_basename)
                if dst:
                    g.add_edge(owner, dst)

    return g


def get_dependency_graph(facts: Facts) -> DependencyGraph:
    """Get (or build) cached dependency graph for a Facts instance."""
    cached = getattr(facts, "_dependency_graph", None)
    if isinstance(cached, DependencyGraph):
        return cached

    g = build_dependency_graph(facts)
    try:
        facts._dependency_graph = g  # type: ignore[attr-defined]
    except Exception:
        pass
    return g


def strongly_connected_components(outgoing: dict[str, set[str]]) -> list[list[str]]:
    """Tarjan SCC (deterministic order by iterating sorted nodes/edges)."""
    index = 0
    stack: list[str] = []
    on_stack: set[str] = set()
    indices: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    comps: list[list[str]] = []

    def strongconnect(v: str) -> None:
        nonlocal index
        indices[v] = index
        lowlink[v] = index
        index += 1
        stack.append(v)
        on_stack.add(v)

        for w in sorted(outgoing.get(v, set())):
            if w not in indices:
                strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif w in on_stack:
                lowlink[v] = min(lowlink[v], indices[w])

        if lowlink[v] == indices[v]:
            comp: list[str] = []
            while True:
                w = stack.pop()
                on_stack.remove(w)
                comp.append(w)
                if w == v:
                    break
            comps.append(comp)

    for v in sorted(outgoing.keys()):
        if v not in indices:
            strongconnect(v)

    return comps

