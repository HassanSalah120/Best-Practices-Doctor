"""
Call Graph / Reference Index (Derived)

Builds a lightweight reference index from existing AST facts.
This is used for safe dead-code heuristics (unused symbols) without doing heavy analysis.

Important:
- Tree-sitter remains the source of truth for structural facts.
- This index is derived from Facts and is cached on the Facts instance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re

from schemas.facts import Facts, ClassInfo, MethodInfo


_INTERNAL_MEMBER_CALL = re.compile(r"\$this->\s*(?P<name>[A-Za-z_]\w*)\s*\(")
_INTERNAL_SCOPED_CALL = re.compile(r"(?:self|static|parent)::\s*(?P<name>[A-Za-z_]\w*)\s*\(")
_SCOPED_CALL = re.compile(r"^\s*\\?(?P<class>[A-Za-z_][A-Za-z0-9_\\\\]*)::\s*(?P<name>[A-Za-z_]\w*)\s*\(")
_SCOPED_CLASS_REF = re.compile(r"\\?(?P<class>[A-Za-z_][A-Za-z0-9_\\\\]*)::")


def _base_name(type_or_fqcn: str) -> str:
    s = (type_or_fqcn or "").strip().lstrip("\\")
    if not s:
        return ""
    return s.split("\\")[-1]


def _parse_param_type(raw: str) -> str | None:
    """
    Parse a best-effort type name from a method parameter node text.

    Handles:
    - "Type $var"
    - "?Type $var"
    - "Type|Foo $var" (picks first non-null)
    - "private readonly Type $var" (property promotion)
    """
    if not raw:
        return None

    s = str(raw).strip()
    s = re.sub(r"^\s*(?:public|protected|private)\s+", "", s)
    s = re.sub(r"^\s*readonly\s+", "", s)

    # Extract first token (type) and variable name token.
    m = re.match(r"^(?P<type>[^\s$]+)\s+(?P<var>\$\w+)\b", s)
    if not m:
        return None

    t = (m.group("type") or "").strip()
    if not t:
        return None

    # Union/nullable normalization.
    t = t.lstrip("?")
    if "|" in t:
        parts = [p for p in t.split("|") if p and p.lower() != "null"]
        if not parts:
            return None
        t = parts[0].lstrip("?")

    t = t.strip().lstrip("\\")
    if not t:
        return None

    # Ignore built-in scalar types.
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


@dataclass
class CallGraphIndex:
    # Definitions
    classes_by_fqcn: dict[str, ClassInfo] = field(default_factory=dict)
    methods_by_fqn: dict[str, MethodInfo] = field(default_factory=dict)
    methods_by_class: dict[str, list[MethodInfo]] = field(default_factory=dict)

    # References
    internal_called_method_names_by_class: dict[str, set[str]] = field(default_factory=dict)
    referenced_class_basenames: set[str] = field(default_factory=set)
    referenced_class_fqcns: set[str] = field(default_factory=set)
    route_targets: dict[str, set[str]] = field(default_factory=dict)  # controller_fqcn -> action names


def build_call_graph_index(facts: Facts) -> CallGraphIndex:
    idx = CallGraphIndex()

    # 1) Definitions
    for c in facts.classes:
        idx.classes_by_fqcn[c.fqcn] = c
        idx.methods_by_class.setdefault(c.fqcn, [])

    for m in facts.methods:
        idx.methods_by_fqn[m.method_fqn] = m
        if m.class_fqcn:
            idx.methods_by_class.setdefault(m.class_fqcn, []).append(m)

    # 2) References from methods
    for m in facts.methods:
        cls = m.class_fqcn

        # DI + method injection (type-hinted params)
        for p in m.parameters or []:
            t = _parse_param_type(p)
            if not t:
                continue
            idx.referenced_class_fqcns.add(t)
            idx.referenced_class_basenames.add(_base_name(t))

        # Instantiations
        for inst in m.instantiations or []:
            s = str(inst).strip().lstrip("\\")
            if not s:
                continue
            idx.referenced_class_fqcns.add(s)
            idx.referenced_class_basenames.add(_base_name(s))

        # Calls
        for cs in m.call_sites or []:
            call = str(cs)

            if cls:
                internal_names = idx.internal_called_method_names_by_class.setdefault(cls, set())
                for mm in _INTERNAL_MEMBER_CALL.finditer(call):
                    internal_names.add(mm.group("name"))
                for sm in _INTERNAL_SCOPED_CALL.finditer(call):
                    internal_names.add(sm.group("name"))

            cm = _SCOPED_CALL.match(call)
            if cm:
                c_name = (cm.group("class") or "").strip().lstrip("\\")
                if c_name:
                    idx.referenced_class_fqcns.add(c_name)
                    idx.referenced_class_basenames.add(_base_name(c_name))

            # Also collect class references embedded within expressions, e.g. `app(Foo::class)`.
            for rm in _SCOPED_CLASS_REF.finditer(call):
                c_name = (rm.group("class") or "").strip().lstrip("\\")
                if not c_name:
                    continue
                if c_name.lower() in {"self", "static", "parent"}:
                    continue
                idx.referenced_class_fqcns.add(c_name)
                idx.referenced_class_basenames.add(_base_name(c_name))

    # 2.1) References from class-constant access expressions (global)
    # This matters for Laravel container binding maps that live in class constants/properties.
    for ref in getattr(facts, "class_const_accesses", []) or []:
        expr = str(getattr(ref, "expression", "") or "")
        for rm in _SCOPED_CLASS_REF.finditer(expr):
            c_name = (rm.group("class") or "").strip().lstrip("\\")
            if not c_name:
                continue
            if c_name.lower() in {"self", "static", "parent"}:
                continue
            idx.referenced_class_fqcns.add(c_name)
            idx.referenced_class_basenames.add(_base_name(c_name))

    # 3) Route targets (controller -> action)
    for r in facts.routes:
        controller = (r.controller or "").strip()
        action = (r.action or "").strip()
        if not controller or not action:
            continue
        controller = controller.lstrip("\\")
        idx.route_targets.setdefault(controller, set()).add(action)
        idx.referenced_class_fqcns.add(controller)
        idx.referenced_class_basenames.add(_base_name(controller))

    return idx


def get_call_graph_index(facts: Facts) -> CallGraphIndex:
    """
    Get (or build) the cached CallGraphIndex for a Facts instance.

    Cached via Facts private attribute to avoid repeated indexing in multiple rules.
    """
    cached = getattr(facts, "_call_graph_index", None)
    if isinstance(cached, CallGraphIndex):
        return cached

    idx = build_call_graph_index(facts)
    try:
        facts._call_graph_index = idx  # type: ignore[attr-defined]
    except Exception:
        pass
    return idx
