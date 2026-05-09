"""
Project Intelligence Map + Project Explainer (additive, non-breaking).

This module builds a static-analysis-driven architecture map and explainer payload from
existing scan facts. It is intentionally deterministic and local-only (no LLM/network).

Design goals:
- Reuse existing AST facts and derived graphs.
- Keep generation safe via traversal guards.
- Persist artifacts so API endpoints can serve map/explainer without rescanning.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import defaultdict, deque
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from analysis.dependency_graph import get_dependency_graph
from schemas.facts import Facts, MethodInfo
from schemas.report import ScanReport

_THIS_MEMBER_CALL = re.compile(r"\$this->\s*(?P<name>[A-Za-z_]\w*)\s*\(")
_SCOPED_INTERNAL_CALL = re.compile(r"(?:self|static|parent)::\s*(?P<name>[A-Za-z_]\w*)\s*\(")
_SCOPED_EXTERNAL_CALL = re.compile(
    r"\\?(?P<class>[A-Za-z_][A-Za-z0-9_\\\\]*)::\s*(?P<name>[A-Za-z_]\w*)\s*\(",
)

_DEFAULT_FRONTEND_EXTS = (".tsx", ".ts", ".jsx", ".js")
_DEFAULT_IMPORT_RESOLUTION_SUFFIXES = (
    "",
    ".tsx",
    ".ts",
    ".jsx",
    ".js",
    "/index.tsx",
    "/index.ts",
    "/index.jsx",
    "/index.js",
)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _stable_short_hash(raw: str, length: int = 12) -> str:
    return hashlib.sha1(str(raw or "").encode("utf-8", errors="ignore")).hexdigest()[:length]


def _stable_id(prefix: str, raw: str) -> str:
    return f"{prefix}:{_stable_short_hash(raw)}"


def _normalized_path(path: str) -> str:
    return str(path or "").replace("\\", "/").strip()


def _class_base_name(raw: str) -> str:
    s = str(raw or "").strip().lstrip("\\")
    if not s:
        return ""
    return s.split("\\")[-1]


def _resolve_class_name(
    raw: str,
    classes_by_fqcn: dict[str, Any],
    by_basename: dict[str, set[str]],
) -> str | None:
    candidate = str(raw or "").strip().lstrip("\\")
    if not candidate:
        return None
    if candidate in classes_by_fqcn:
        return candidate
    if "\\" in candidate:
        return None
    choices = by_basename.get(candidate, set())
    if len(choices) == 1:
        return next(iter(choices))
    return None


def _severity_rank(value: str) -> int:
    s = str(value or "").lower()
    if s == "critical":
        return 5
    if s == "high":
        return 4
    if s == "medium":
        return 3
    if s == "low":
        return 2
    if s == "info":
        return 1
    return 0


@dataclass(slots=True)
class TraversalCaps:
    max_nodes_per_flow: int = 320
    max_depth: int = 20
    max_endpoint_flows: int = 400
    max_component_flows: int = 400
    max_nodes_total: int = 7000
    max_edges_total: int = 16000


class ProjectMapArtifactStore:
    """Persistent JSON artifact store for project-map / explainer payloads."""

    CACHE_DIR = "project_map_artifacts"
    INDEX_FILE = "index.json"

    def __init__(self, root_dir: Path | None = None) -> None:
        app_data = os.environ.get("BPD_APP_DATA_DIR")
        base = root_dir or (Path(app_data) if app_data else (Path.home() / ".bpd"))
        self.root = base / self.CACHE_DIR
        self.root.mkdir(parents=True, exist_ok=True)

    def _project_hash(self, project_path: str) -> str:
        return _stable_short_hash(str(Path(project_path).resolve()), length=16)

    def _project_dir(self, project_path: str) -> Path:
        d = self.root / self._project_hash(project_path)
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _index_path(self, project_path: str) -> Path:
        return self._project_dir(project_path) / self.INDEX_FILE

    def _load_index(self, project_path: str) -> dict[str, Any]:
        p = self._index_path(project_path)
        try:
            if p.exists():
                payload = json.loads(p.read_text(encoding="utf-8") or "{}")
                if isinstance(payload, dict):
                    payload.setdefault("by_signature", {})
                    payload.setdefault("by_scan", {})
                    return payload
        except Exception:
            pass
        return {"by_signature": {}, "by_scan": {}}

    def _save_index(self, project_path: str, data: dict[str, Any]) -> None:
        p = self._index_path(project_path)
        p.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

    def _artifact_path(self, project_path: str, signature: str) -> Path:
        return self._project_dir(project_path) / f"artifact-{signature}.json"

    @staticmethod
    def compute_signature(facts: Facts) -> str:
        file_hashes = dict(getattr(facts, "file_hashes", {}) or {})
        stable = {
            "files": sorted((str(k), str(v)) for k, v in file_hashes.items()),
            "routes": len(getattr(facts, "routes", []) or []),
            "classes": len(getattr(facts, "classes", []) or []),
            "methods": len(getattr(facts, "methods", []) or []),
            "components": len(getattr(facts, "react_components", []) or []),
        }
        raw = json.dumps(stable, sort_keys=True, default=str)
        return _stable_short_hash(raw, length=16)

    def save(
        self,
        *,
        project_path: str,
        scan_id: str,
        signature: str,
        artifact: dict[str, Any],
    ) -> None:
        artifact_path = self._artifact_path(project_path, signature)
        tmp = artifact_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(artifact, indent=2, sort_keys=False), encoding="utf-8")
        tmp.replace(artifact_path)

        index = self._load_index(project_path)
        index["latest_signature"] = signature
        index["latest_scan_id"] = scan_id
        index.setdefault("by_signature", {})[signature] = artifact_path.name
        index.setdefault("by_scan", {})[scan_id] = artifact_path.name
        self._save_index(project_path, index)

    def _load_by_path(self, file_path: Path) -> dict[str, Any] | None:
        try:
            if not file_path.exists():
                return None
            payload = json.loads(file_path.read_text(encoding="utf-8") or "{}")
            if isinstance(payload, dict):
                return payload
        except Exception:
            return None
        return None

    def load_by_signature(self, *, project_path: str, signature: str) -> dict[str, Any] | None:
        index = self._load_index(project_path)
        rel = str(index.get("by_signature", {}).get(signature, "") or "")
        if not rel:
            return None
        payload = self._load_by_path(self._project_dir(project_path) / rel)
        return payload

    def load_by_scan(self, *, project_path: str, scan_id: str) -> dict[str, Any] | None:
        index = self._load_index(project_path)
        rel = str(index.get("by_scan", {}).get(scan_id, "") or "")
        if rel:
            payload = self._load_by_path(self._project_dir(project_path) / rel)
            if payload is not None:
                return payload
        # Fallback to latest artifact for this project.
        latest_sig = str(index.get("latest_signature", "") or "")
        if not latest_sig:
            return None
        return self.load_by_signature(project_path=project_path, signature=latest_sig)

    def attach_scan_to_signature(self, *, project_path: str, scan_id: str, signature: str) -> None:
        index = self._load_index(project_path)
        rel = str(index.get("by_signature", {}).get(signature, "") or "")
        if not rel:
            return
        index["latest_signature"] = signature
        index["latest_scan_id"] = scan_id
        index.setdefault("by_scan", {})[scan_id] = rel
        self._save_index(project_path, index)


class ProjectMapBuilder:
    """Builds the project map graph, hierarchy, insights, and explainer payload."""

    def __init__(self, caps: TraversalCaps | None = None) -> None:
        self.caps = caps or TraversalCaps()

    def build_and_cache(
        self,
        *,
        facts: Facts,
        report: ScanReport,
        store: ProjectMapArtifactStore | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """
        Build artifact with cache reuse.

        Returns:
            artifact payload
            cache metadata
        """
        artifact_store = store or ProjectMapArtifactStore()
        signature = artifact_store.compute_signature(facts)
        cached = artifact_store.load_by_signature(
            project_path=report.project_path,
            signature=signature,
        )
        if isinstance(cached, dict):
            artifact_store.attach_scan_to_signature(
                project_path=report.project_path,
                scan_id=report.id,
                signature=signature,
            )
            payload = deepcopy(cached)
            meta = dict(payload.get("meta") or {})
            meta["cache_hit"] = True
            meta["scan_id"] = report.id
            meta["generated_at"] = _now_iso()
            payload["meta"] = meta
            return payload, {"cache_hit": True, "signature": signature}

        payload = self.build(facts=facts, report=report, signature=signature)
        artifact_store.save(
            project_path=report.project_path,
            scan_id=report.id,
            signature=signature,
            artifact=payload,
        )
        return payload, {"cache_hit": False, "signature": signature}

    def build(self, *, facts: Facts, report: ScanReport, signature: str) -> dict[str, Any]:
        node_map: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []
        edge_seen: set[tuple[str, str, str]] = set()
        truncated_flags: list[str] = []

        def add_node(
            *,
            node_id: str,
            node_type: str,
            label: str,
            file_path: str = "",
            metadata: dict[str, Any] | None = None,
        ) -> None:
            if node_id in node_map:
                return
            if len(node_map) >= self.caps.max_nodes_total:
                if "max_nodes_total" not in truncated_flags:
                    truncated_flags.append("max_nodes_total")
                return
            node_map[node_id] = {
                "id": node_id,
                "type": node_type,
                "label": label,
                "file": _normalized_path(file_path),
                "metadata": dict(metadata or {}),
            }

        def add_edge(
            *,
            src: str,
            dst: str,
            edge_type: str,
            metadata: dict[str, Any] | None = None,
        ) -> None:
            if src == dst:
                return
            key = (src, dst, edge_type)
            if key in edge_seen:
                return
            if len(edges) >= self.caps.max_edges_total:
                if "max_edges_total" not in truncated_flags:
                    truncated_flags.append("max_edges_total")
                return
            edge_seen.add(key)
            edges.append(
                {
                    "from": src,
                    "to": dst,
                    "type": edge_type,
                    "metadata": dict(metadata or {}),
                },
            )

        classes = list(getattr(facts, "classes", []) or [])
        methods = list(getattr(facts, "methods", []) or [])
        routes = list(getattr(facts, "routes", []) or [])
        react_components = list(getattr(facts, "react_components", []) or [])

        classes_by_fqcn = {str(c.fqcn).lstrip("\\"): c for c in classes}
        classes_by_basename: dict[str, set[str]] = defaultdict(set)
        for fqcn in classes_by_fqcn:
            classes_by_basename[_class_base_name(fqcn)].add(fqcn)

        controllers = {str(c.fqcn).lstrip("\\") for c in (getattr(facts, "controllers", []) or [])}
        services = {str(c.fqcn).lstrip("\\") for c in (getattr(facts, "services", []) or [])}
        models = {str(c.fqcn).lstrip("\\") for c in (getattr(facts, "models", []) or [])}

        class_kind: dict[str, str] = {}
        for fqcn in classes_by_fqcn:
            if fqcn in controllers:
                class_kind[fqcn] = "controller"
            elif fqcn in services:
                class_kind[fqcn] = "service"
            elif fqcn in models:
                class_kind[fqcn] = "model"
            else:
                class_kind[fqcn] = "class"

        method_nodes_by_key: dict[tuple[str, str, int], str] = {}
        method_nodes_by_name: dict[tuple[str, str], list[str]] = defaultdict(list)
        method_info_by_node: dict[str, MethodInfo] = {}
        methods_by_class: dict[str, list[MethodInfo]] = defaultdict(list)

        # Class + method nodes.
        for fqcn, c in classes_by_fqcn.items():
            class_id = f"class:{fqcn}"
            add_node(
                node_id=class_id,
                node_type=class_kind.get(fqcn, "class"),
                label=_class_base_name(fqcn),
                file_path=c.file_path,
                metadata={
                    "fqcn": fqcn,
                    "namespace": str(c.namespace or ""),
                    "line_start": int(c.line_start or 0),
                    "line_end": int(c.line_end or 0),
                },
            )

        for m in methods:
            owner = str(m.class_fqcn or "").lstrip("\\")
            if not owner:
                continue
            methods_by_class[owner].append(m)
            method_id = f"method:{owner}::{m.name}#{int(m.line_start or 0)}"
            method_nodes_by_key[(owner, str(m.name), int(m.line_start or 0))] = method_id
            method_nodes_by_name[(owner, str(m.name))].append(method_id)
            method_info_by_node[method_id] = m
            add_node(
                node_id=method_id,
                node_type="method",
                label=f"{_class_base_name(owner)}::{m.name}",
                file_path=m.file_path,
                metadata={
                    "class_fqcn": owner,
                    "method_name": str(m.name),
                    "visibility": str(m.visibility or "public"),
                    "line_start": int(m.line_start or 0),
                    "line_end": int(m.line_end or 0),
                    "loc": int(m.loc or 0),
                },
            )
            add_edge(src=f"class:{owner}", dst=method_id, edge_type="contains")

        # Route nodes + route->controller/method relations.
        route_entry_method_ids: set[str] = set()
        route_node_ids: list[str] = []
        endpoint_catalog: list[dict[str, Any]] = []
        for r in routes:
            route_key = f"{r.method}|{r.uri}|{r.controller or ''}|{r.action or ''}|{r.file_path}|{r.line_number}"
            route_id = _stable_id("route", route_key)
            route_node_ids.append(route_id)
            add_node(
                node_id=route_id,
                node_type="route",
                label=f"{str(r.method or '').upper()} {str(r.uri or '').strip()}",
                file_path=r.file_path,
                metadata={
                    "method": str(r.method or "").upper(),
                    "uri": str(r.uri or ""),
                    "name": str(r.name or ""),
                    "controller": str(r.controller or ""),
                    "action": str(r.action or ""),
                    "middleware": list(getattr(r, "middleware", []) or []),
                    "line_number": int(getattr(r, "line_number", 0) or 0),
                },
            )

            controller_fqcn = _resolve_class_name(r.controller or "", classes_by_fqcn, classes_by_basename)
            method_name = str(r.action or "").strip() or "__invoke"
            method_id: str | None = None

            if controller_fqcn:
                class_id = f"class:{controller_fqcn}"
                add_edge(src=route_id, dst=class_id, edge_type="uses")
                candidates = method_nodes_by_name.get((controller_fqcn, method_name), [])
                if candidates:
                    method_id = sorted(candidates)[0]
                    add_edge(src=route_id, dst=method_id, edge_type="calls")
                    route_entry_method_ids.add(method_id)

            endpoint_catalog.append(
                {
                    "entry_id": route_id,
                    "framework": "laravel",
                    "method": str(r.method or "").upper(),
                    "uri": str(r.uri or ""),
                    "route_name": str(r.name or ""),
                    "controller": str(controller_fqcn or r.controller or ""),
                    "action": method_name,
                    "middleware": list(getattr(r, "middleware", []) or []),
                    "file": _normalized_path(str(r.file_path or "")),
                    "line": int(getattr(r, "line_number", 0) or 0),
                    "entry_method_id": method_id,
                },
            )

        # Method call/usage edges.
        for src_node_id, method in method_info_by_node.items():
            owner = str(method.class_fqcn or "").lstrip("\\")
            if not owner:
                continue

            for call in list(getattr(method, "call_sites", []) or []):
                raw_call = str(call or "")
                if not raw_call:
                    continue

                for match in _THIS_MEMBER_CALL.finditer(raw_call):
                    target_name = str(match.group("name") or "")
                    for dst in method_nodes_by_name.get((owner, target_name), []):
                        add_edge(src=src_node_id, dst=dst, edge_type="calls")

                for match in _SCOPED_INTERNAL_CALL.finditer(raw_call):
                    target_name = str(match.group("name") or "")
                    for dst in method_nodes_by_name.get((owner, target_name), []):
                        add_edge(src=src_node_id, dst=dst, edge_type="calls")

                for match in _SCOPED_EXTERNAL_CALL.finditer(raw_call):
                    target_class_raw = str(match.group("class") or "")
                    target_method_name = str(match.group("name") or "")
                    target_class = _resolve_class_name(
                        target_class_raw,
                        classes_by_fqcn,
                        classes_by_basename,
                    )
                    if not target_class:
                        continue
                    target_method_ids = method_nodes_by_name.get((target_class, target_method_name), [])
                    if target_method_ids:
                        add_edge(src=src_node_id, dst=sorted(target_method_ids)[0], edge_type="calls")
                    else:
                        add_edge(src=src_node_id, dst=f"class:{target_class}", edge_type="uses")

            for inst in list(getattr(method, "instantiations", []) or []):
                target_class = _resolve_class_name(inst, classes_by_fqcn, classes_by_basename)
                if target_class:
                    add_edge(src=src_node_id, dst=f"class:{target_class}", edge_type="uses")

        # Dependency graph edges (class-level + method-level hints).
        dep_graph = get_dependency_graph(facts)
        for src_class, targets in dict(getattr(dep_graph, "outgoing", {}) or {}).items():
            src_norm = str(src_class or "").lstrip("\\")
            if src_norm not in classes_by_fqcn:
                continue
            src_class_id = f"class:{src_norm}"
            for target in sorted(set(targets or [])):
                dst_norm = str(target or "").lstrip("\\")
                if dst_norm not in classes_by_fqcn:
                    continue
                dst_class_id = f"class:{dst_norm}"
                add_edge(src=src_class_id, dst=dst_class_id, edge_type="depends_on")
                for method in methods_by_class.get(src_norm, []):
                    method_id = f"method:{src_norm}::{method.name}#{int(method.line_start or 0)}"
                    if method_id in method_info_by_node:
                        add_edge(src=method_id, dst=dst_class_id, edge_type="depends_on")

        # Frontend nodes/edges.
        frontend_graph = getattr(facts, "_frontend_symbol_graph", None)
        files_graph = {}
        frontend_edges_raw: list[dict[str, Any]] = []
        if isinstance(frontend_graph, dict):
            files_graph = dict(frontend_graph.get("files") or {})
            frontend_edges_raw = list(frontend_graph.get("edges") or [])

        frontend_files = set(_normalized_path(p) for p in files_graph.keys())
        frontend_files.update(_normalized_path(c.file_path) for c in react_components)
        frontend_files = {p for p in frontend_files if p}

        components_by_file: dict[str, list[dict[str, Any]]] = defaultdict(list)
        component_ids: list[str] = []
        page_component_ids: list[str] = []
        hook_ids: set[str] = set()

        for comp in react_components:
            file_path = _normalized_path(comp.file_path)
            if not file_path:
                continue
            component_id = f"component:{file_path}:{comp.name}"
            component_ids.append(component_id)
            is_page = "/pages/" in f"/{file_path.lower()}/" or file_path.lower().endswith("/page.tsx")
            if is_page:
                page_component_ids.append(component_id)
            add_node(
                node_id=component_id,
                node_type="page" if is_page else "component",
                label=str(comp.name),
                file_path=file_path,
                metadata={
                    "name": str(comp.name),
                    "loc": int(getattr(comp, "loc", 0) or 0),
                    "line_start": int(getattr(comp, "line_start", 0) or 0),
                    "line_end": int(getattr(comp, "line_end", 0) or 0),
                    "framework": "react",
                },
            )
            components_by_file[file_path].append({"id": component_id, "name": str(comp.name)})

            hooks = sorted(set(list(getattr(comp, "hooks_used", []) or [])))
            for hook in hooks:
                hook_id = f"hook:{hook}"
                hook_ids.add(hook_id)
                add_node(
                    node_id=hook_id,
                    node_type="hook",
                    label=hook,
                    metadata={"framework": "react"},
                )
                add_edge(src=component_id, dst=hook_id, edge_type="uses")

        file_nodes: list[str] = []
        for file_path in sorted(frontend_files):
            file_id = f"file:{file_path}"
            file_nodes.append(file_id)
            add_node(
                node_id=file_id,
                node_type="file",
                label=file_path.split("/")[-1],
                file_path=file_path,
                metadata={"framework": "react"},
            )
            for comp in components_by_file.get(file_path, []):
                add_edge(src=file_id, dst=str(comp["id"]), edge_type="contains")

        def resolve_import(file_path: str, import_value: str) -> str | None:
            target = str(import_value or "").strip()
            if not target or not target.startswith("."):
                return None
            base = Path(file_path).parent
            for suffix in _DEFAULT_IMPORT_RESOLUTION_SUFFIXES:
                candidate = _normalized_path(str((base / f"{target}{suffix}").as_posix()))
                if candidate in frontend_files:
                    return candidate
            return None

        # Component renders/import edges from per-file symbol graph.
        for src_file, payload in files_graph.items():
            src_file_norm = _normalized_path(src_file)
            imports = list((payload or {}).get("imports") or [])
            if not src_file_norm:
                continue
            src_components = components_by_file.get(src_file_norm, [])
            src_file_id = f"file:{src_file_norm}"
            for imp in imports:
                imp_raw = str(imp or "").strip()
                if not imp_raw:
                    continue
                resolved = resolve_import(src_file_norm, imp_raw)
                if resolved:
                    dst_file_id = f"file:{resolved}"
                    add_edge(src=src_file_id, dst=dst_file_id, edge_type="imports")
                    for src_comp in src_components:
                        for dst_comp in components_by_file.get(resolved, []):
                            add_edge(src=str(src_comp["id"]), dst=str(dst_comp["id"]), edge_type="renders")
                else:
                    module_id = f"module:{imp_raw}"
                    add_node(
                        node_id=module_id,
                        node_type="module",
                        label=imp_raw,
                        metadata={"external": True, "framework": "react"},
                    )
                    add_edge(src=src_file_id, dst=module_id, edge_type="imports")
                    for src_comp in src_components:
                        add_edge(src=str(src_comp["id"]), dst=module_id, edge_type="imports")

        # Keep raw symbol graph edges as fallback import edges when useful.
        for raw_edge in frontend_edges_raw:
            src_file = _normalized_path(str(raw_edge.get("from") or ""))
            dst_raw = str(raw_edge.get("to") or "")
            if not src_file or not dst_raw:
                continue
            src_file_id = f"file:{src_file}"
            resolved = resolve_import(src_file, dst_raw)
            if resolved:
                add_edge(src=src_file_id, dst=f"file:{resolved}", edge_type="imports")
            else:
                module_id = f"module:{dst_raw}"
                add_node(node_id=module_id, node_type="module", label=dst_raw, metadata={"external": True})
                add_edge(src=src_file_id, dst=module_id, edge_type="imports")

        nodes = sorted(node_map.values(), key=lambda n: (str(n.get("type", "")), str(n.get("label", "")), str(n.get("id", ""))))
        edges.sort(key=lambda e: (str(e.get("type", "")), str(e.get("from", "")), str(e.get("to", ""))))

        adjacency_out: dict[str, list[dict[str, Any]]] = defaultdict(list)
        adjacency_in: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for e in edges:
            adjacency_out[str(e["from"])].append(e)
            adjacency_in[str(e["to"])].append(e)

        hierarchy = self._build_hierarchy(
            routes=routes,
            endpoint_catalog=endpoint_catalog,
            classes_by_fqcn=classes_by_fqcn,
            class_kind=class_kind,
            methods_by_class=methods_by_class,
            page_component_ids=page_component_ids,
            component_ids=component_ids,
            hook_ids=hook_ids,
            components_by_file=components_by_file,
            frontend_files=sorted(frontend_files),
        )

        insights = self._build_insights(
            nodes=nodes,
            edges=edges,
            class_kind=class_kind,
            methods_by_class=methods_by_class,
            method_info_by_node=method_info_by_node,
            route_entry_method_ids=route_entry_method_ids,
            route_node_ids=set(route_node_ids),
            page_component_ids=set(page_component_ids),
            component_ids=set(component_ids),
            adjacency_in=adjacency_in,
            dep_graph=dep_graph,
            report=report,
        )

        explainer = self._build_explainer(
            nodes=nodes,
            edges=edges,
            endpoint_catalog=endpoint_catalog,
            route_entry_method_ids=route_entry_method_ids,
            adjacency_out=adjacency_out,
            adjacency_in=adjacency_in,
            insights=insights,
            hierarchy=hierarchy,
            truncated_flags=truncated_flags,
        )
        explainer_summary = self._build_explainer_summary(explainer)

        meta = {
            "version": 1,
            "scan_id": report.id,
            "project_hash": _stable_short_hash(str(Path(report.project_path).resolve()), length=16),
            "generated_at": _now_iso(),
            "signature": signature,
            "truncated": bool(truncated_flags or explainer.get("truncated")),
            "truncation_reasons": sorted(set(truncated_flags + list(explainer.get("truncation_reasons", []) or []))),
            "cache_hit": False,
            "caps": {
                "max_nodes_per_flow": self.caps.max_nodes_per_flow,
                "max_depth": self.caps.max_depth,
                "max_endpoint_flows": self.caps.max_endpoint_flows,
                "max_component_flows": self.caps.max_component_flows,
                "max_nodes_total": self.caps.max_nodes_total,
                "max_edges_total": self.caps.max_edges_total,
            },
            "counts": {
                "nodes": len(nodes),
                "edges": len(edges),
                "routes": len(routes),
                "classes": len(classes),
                "methods": len(methods),
                "components": len(react_components),
            },
        }

        return {
            "nodes": nodes,
            "edges": edges,
            "hierarchy": hierarchy,
            "insights": insights,
            "explainer": explainer,
            "explainer_summary": explainer_summary,
            "meta": meta,
        }

    def _build_hierarchy(
        self,
        *,
        routes: list[Any],
        endpoint_catalog: list[dict[str, Any]],
        classes_by_fqcn: dict[str, Any],
        class_kind: dict[str, str],
        methods_by_class: dict[str, list[MethodInfo]],
        page_component_ids: list[str],
        component_ids: list[str],
        hook_ids: set[str],
        components_by_file: dict[str, list[dict[str, Any]]],
        frontend_files: list[str],
    ) -> dict[str, Any]:
        routes_tree = []
        for entry in endpoint_catalog:
            routes_tree.append(
                {
                    "id": entry.get("entry_id"),
                    "label": f"{entry.get('method', '')} {entry.get('uri', '')}".strip(),
                    "type": "route",
                    "method": entry.get("method", ""),
                    "uri": entry.get("uri", ""),
                    "controller": entry.get("controller", ""),
                    "action": entry.get("action", ""),
                    "children": [entry.get("entry_method_id")] if entry.get("entry_method_id") else [],
                },
            )

        def class_tree(kind: str) -> list[dict[str, Any]]:
            out: list[dict[str, Any]] = []
            for fqcn, c in sorted(classes_by_fqcn.items(), key=lambda kv: kv[0]):
                if class_kind.get(fqcn) != kind:
                    continue
                method_children = []
                for m in sorted(methods_by_class.get(fqcn, []), key=lambda item: (item.name, int(item.line_start or 0))):
                    method_children.append(
                        {
                            "id": f"method:{fqcn}::{m.name}#{int(m.line_start or 0)}",
                            "label": f"{m.name}()",
                            "type": "method",
                        },
                    )
                out.append(
                    {
                        "id": f"class:{fqcn}",
                        "label": _class_base_name(fqcn),
                        "type": kind,
                        "file": _normalized_path(str(c.file_path or "")),
                        "children": method_children,
                    },
                )
            return out

        page_nodes = [{"id": pid, "label": pid.split(":")[-1], "type": "page"} for pid in sorted(set(page_component_ids))]
        component_nodes = [{"id": cid, "label": cid.split(":")[-1], "type": "component"} for cid in sorted(set(component_ids))]
        hook_nodes = [{"id": hid, "label": hid.split(":", 1)[-1], "type": "hook"} for hid in sorted(hook_ids)]
        file_nodes = []
        for p in frontend_files:
            file_nodes.append(
                {
                    "id": f"file:{p}",
                    "label": p,
                    "type": "file",
                    "children": [dict(item) for item in components_by_file.get(p, [])],
                },
            )
        return {
            "backend": {
                "routes": routes_tree,
                "controllers": class_tree("controller"),
                "services": class_tree("service"),
                "models": class_tree("model"),
            },
            "frontend": {
                "pages": page_nodes,
                "components": component_nodes,
                "hooks": hook_nodes,
                "files": file_nodes,
            },
            "summary": {
                "route_count": len(routes),
                "controller_count": len(class_tree("controller")),
                "service_count": len(class_tree("service")),
                "model_count": len(class_tree("model")),
                "page_count": len(page_nodes),
                "component_count": len(component_nodes),
                "hook_count": len(hook_nodes),
            },
        }

    def _build_insights(
        self,
        *,
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
        class_kind: dict[str, str],
        methods_by_class: dict[str, list[MethodInfo]],
        method_info_by_node: dict[str, MethodInfo],
        route_entry_method_ids: set[str],
        route_node_ids: set[str],
        page_component_ids: set[str],
        component_ids: set[str],
        adjacency_in: dict[str, list[dict[str, Any]]],
        dep_graph: Any,
        report: ScanReport,
    ) -> dict[str, Any]:
        warnings: list[dict[str, Any]] = []

        def push_warning(
            *,
            warning_type: str,
            node_id: str,
            severity: str,
            title: str,
            description: str,
            metadata: dict[str, Any] | None = None,
        ) -> None:
            warnings.append(
                {
                    "id": _stable_id("warn", f"{warning_type}|{node_id}|{title}"),
                    "type": warning_type,
                    "node_id": node_id,
                    "severity": severity,
                    "title": title,
                    "description": description,
                    "metadata": dict(metadata or {}),
                },
            )

        # Dead methods: no inbound calls and not route entrypoints and not magic methods.
        dead_methods: list[dict[str, Any]] = []
        for node_id, info in method_info_by_node.items():
            method_name = str(info.name or "")
            if method_name.startswith("__"):
                continue
            inbound = list(adjacency_in.get(node_id, []))
            has_callers = any(str(e.get("type")) in {"calls"} for e in inbound)
            if has_callers or node_id in route_entry_method_ids:
                continue
            dead_methods.append(
                {
                    "id": node_id,
                    "label": f"{_class_base_name(str(info.class_fqcn or ''))}::{info.name}",
                    "file": _normalized_path(info.file_path),
                    "line_start": int(info.line_start or 0),
                },
            )
            push_warning(
                warning_type="dead_method",
                node_id=node_id,
                severity="medium",
                title="Method appears unused",
                description=f"{info.name}() has no detected callers in static map.",
            )

        # Controllers not used by routes.
        controllers_unused: list[dict[str, Any]] = []
        controller_nodes = {f"class:{fqcn}" for fqcn, kind in class_kind.items() if kind == "controller"}
        for node_id in sorted(controller_nodes):
            inbound = list(adjacency_in.get(node_id, []))
            referenced_by_route = any(str(e.get("from", "")) in route_node_ids for e in inbound)
            if referenced_by_route:
                continue
            controllers_unused.append({"id": node_id, "label": node_id.split(":")[-1]})
            push_warning(
                warning_type="unused_controller",
                node_id=node_id,
                severity="medium",
                title="Controller not referenced by routes",
                description="No route -> controller relation was detected for this controller.",
            )

        # Components never imported/rendered and not page entrypoints.
        component_incoming: dict[str, int] = defaultdict(int)
        for e in edges:
            if str(e.get("to", "")) in component_ids and str(e.get("type", "")) in {"renders", "imports", "contains"}:
                component_incoming[str(e["to"])] += 1
        components_unused: list[dict[str, Any]] = []
        for cid in sorted(component_ids):
            if cid in page_component_ids:
                continue
            if component_incoming.get(cid, 0) > 0:
                continue
            components_unused.append({"id": cid, "label": cid.split(":")[-1]})
            push_warning(
                warning_type="unused_component",
                node_id=cid,
                severity="low",
                title="Component appears unused",
                description="Component has no detected incoming imports/renders.",
            )

        # Coupling and god-class candidates from dependency graph + method density.
        high_coupling: list[dict[str, Any]] = []
        god_class_candidates: list[dict[str, Any]] = []
        dep_outgoing = dict(getattr(dep_graph, "outgoing", {}) or {})
        for fqcn, targets in sorted(dep_outgoing.items()):
            fqcn_norm = str(fqcn).lstrip("\\")
            if fqcn_norm not in class_kind:
                continue
            out_count = len(set(targets or []))
            method_count = len(methods_by_class.get(fqcn_norm, []))
            class_id = f"class:{fqcn_norm}"
            if out_count >= 12:
                high_coupling.append({"id": class_id, "label": _class_base_name(fqcn_norm), "dependency_count": out_count})
                push_warning(
                    warning_type="high_coupling",
                    node_id=class_id,
                    severity="high",
                    title="High coupling",
                    description=f"Class depends on {out_count} other classes.",
                    metadata={"dependency_count": out_count},
                )
            if method_count >= 20 or (method_count >= 14 and out_count >= 10):
                god_class_candidates.append(
                    {
                        "id": class_id,
                        "label": _class_base_name(fqcn_norm),
                        "method_count": method_count,
                        "dependency_count": out_count,
                    },
                )
                push_warning(
                    warning_type="god_class_candidate",
                    node_id=class_id,
                    severity="high",
                    title="Large class candidate",
                    description=f"Class has {method_count} methods and {out_count} dependencies.",
                    metadata={"method_count": method_count, "dependency_count": out_count},
                )

        # Deep call chains from route entry methods.
        call_adj: dict[str, list[str]] = defaultdict(list)
        for e in edges:
            if str(e.get("type", "")) == "calls":
                call_adj[str(e["from"])].append(str(e["to"]))

        deep_call_chains: list[dict[str, Any]] = []

        def dfs_chain(start: str) -> tuple[list[str], bool]:
            best: list[str] = []
            truncated = False
            stack: list[tuple[str, list[str], set[str], int]] = [(start, [start], {start}, 0)]
            while stack:
                node, path, seen, depth = stack.pop()
                if len(path) > len(best):
                    best = path
                if depth >= self.caps.max_depth:
                    truncated = True
                    continue
                children = call_adj.get(node, [])
                for child in children:
                    if child in seen:
                        continue
                    if len(path) >= self.caps.max_nodes_per_flow:
                        truncated = True
                        continue
                    next_seen = set(seen)
                    next_seen.add(child)
                    stack.append((child, [*path, child], next_seen, depth + 1))
            return best, truncated

        for start in sorted(route_entry_method_ids):
            chain, truncated = dfs_chain(start)
            if len(chain) >= 8:
                deep_call_chains.append(
                    {
                        "entry_method_id": start,
                        "depth": len(chain),
                        "path": chain,
                        "truncated": truncated,
                    },
                )
                push_warning(
                    warning_type="deep_call_chain",
                    node_id=start,
                    severity="medium",
                    title="Deep call chain",
                    description=f"Static call depth reached {len(chain)} from this entry method.",
                    metadata={"depth": len(chain), "truncated": truncated},
                )
        deep_call_chains.sort(key=lambda item: (-int(item.get("depth", 0)), str(item.get("entry_method_id", ""))))
        warnings.sort(
            key=lambda item: (
                -_severity_rank(str(item.get("severity", ""))),
                str(item.get("type", "")),
                str(item.get("node_id", "")),
            ),
        )

        findings_by_rule: dict[str, int] = defaultdict(int)
        for f in list(getattr(report, "findings", []) or []):
            findings_by_rule[str(getattr(f, "rule_id", "") or "")] += 1

        return {
            "dead_code": {
                "methods": dead_methods[:250],
                "controllers": controllers_unused[:200],
                "components": components_unused[:300],
            },
            "coupling": {
                "high_coupling": high_coupling[:200],
            },
            "god_classes": god_class_candidates[:200],
            "deep_call_chains": deep_call_chains[:80],
            "warnings": warnings[:600],
            "source_findings_by_rule": dict(sorted(findings_by_rule.items())),
        }

    def _build_explainer(
        self,
        *,
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
        endpoint_catalog: list[dict[str, Any]],
        route_entry_method_ids: set[str],
        adjacency_out: dict[str, list[dict[str, Any]]],
        adjacency_in: dict[str, list[dict[str, Any]]],
        insights: dict[str, Any],
        hierarchy: dict[str, Any],
        truncated_flags: list[str],
    ) -> dict[str, Any]:
        node_by_id = {str(n.get("id", "")): n for n in nodes}
        route_flow_candidates = [entry for entry in endpoint_catalog if entry.get("entry_method_id")]
        route_flow_candidates.sort(key=lambda item: (str(item.get("method", "")), str(item.get("uri", ""))))

        endpoint_flows: list[dict[str, Any]] = []
        endpoint_truncated = False
        for entry in route_flow_candidates[: self.caps.max_endpoint_flows]:
            start_id = str(entry.get("entry_method_id") or "")
            if not start_id:
                continue
            flow = self._traverse_flow(
                start_id=start_id,
                adjacency_out=adjacency_out,
                node_by_id=node_by_id,
                include_edge_types={"calls", "depends_on", "uses"},
            )
            flow["entry_id"] = str(entry.get("entry_id", ""))
            flow["framework"] = "laravel"
            flow["method"] = str(entry.get("method", ""))
            flow["uri"] = str(entry.get("uri", ""))
            flow["controller"] = str(entry.get("controller", ""))
            flow["action"] = str(entry.get("action", ""))
            endpoint_flows.append(flow)
            if bool(flow.get("truncated")):
                endpoint_truncated = True
        if len(route_flow_candidates) > self.caps.max_endpoint_flows:
            endpoint_truncated = True
            if "max_endpoint_flows" not in truncated_flags:
                truncated_flags.append("max_endpoint_flows")

        # Function dependency index.
        dependency_index: dict[str, dict[str, Any]] = {}
        for node in nodes:
            node_id = str(node.get("id", ""))
            node_type = str(node.get("type", ""))
            if node_type not in {"method", "service", "controller", "model", "component", "page", "hook", "class"}:
                continue
            out_edges = list(adjacency_out.get(node_id, []))
            in_edges = list(adjacency_in.get(node_id, []))
            calls = sorted({str(e.get("to", "")) for e in out_edges if str(e.get("type", "")) == "calls"})
            depends_on = sorted(
                {
                    str(e.get("to", ""))
                    for e in out_edges
                    if str(e.get("type", "")) in {"depends_on", "uses", "imports", "renders"}
                },
            )
            called_by = sorted({str(e.get("from", "")) for e in in_edges if str(e.get("type", "")) == "calls"})
            used_by = sorted(
                {
                    str(e.get("from", ""))
                    for e in in_edges
                    if str(e.get("type", "")) in {"depends_on", "uses", "imports", "renders"}
                },
            )
            dependency_index[node_id] = {
                "id": node_id,
                "label": str(node.get("label", "")),
                "type": node_type,
                "file": str(node.get("file", "")),
                "calls": calls,
                "called_by": called_by,
                "depends_on": depends_on,
                "used_by": used_by,
            }

        # Component flows from page entries.
        component_flows: list[dict[str, Any]] = []
        component_starts = [n for n in nodes if str(n.get("id", "")).startswith("component:") or str(n.get("id", "")).startswith("page:")]
        page_ids = [str(n.get("id", "")) for n in nodes if str(n.get("type", "")) == "page"]
        if not page_ids:
            page_ids = [nid for nid in sorted(dependency_index.keys()) if nid.startswith("component:")]
        for start_id in page_ids[: self.caps.max_component_flows]:
            flow = self._traverse_flow(
                start_id=start_id,
                adjacency_out=adjacency_out,
                node_by_id=node_by_id,
                include_edge_types={"renders", "uses", "imports"},
            )
            flow["entry_id"] = start_id
            flow["framework"] = "react"
            component_flows.append(flow)
            if bool(flow.get("truncated")):
                if "flow_truncated" not in truncated_flags:
                    truncated_flags.append("flow_truncated")
        if len(page_ids) > self.caps.max_component_flows and "max_component_flows" not in truncated_flags:
            truncated_flags.append("max_component_flows")

        architecture_overview = {
            "backend": {
                "routes": int(hierarchy.get("summary", {}).get("route_count", 0)),
                "controllers": int(hierarchy.get("summary", {}).get("controller_count", 0)),
                "services": int(hierarchy.get("summary", {}).get("service_count", 0)),
                "models": int(hierarchy.get("summary", {}).get("model_count", 0)),
            },
            "frontend": {
                "pages": int(hierarchy.get("summary", {}).get("page_count", 0)),
                "components": int(hierarchy.get("summary", {}).get("component_count", 0)),
                "hooks": int(hierarchy.get("summary", {}).get("hook_count", 0)),
            },
        }

        narrative_sections = self._build_narrative_sections(
            architecture_overview=architecture_overview,
            endpoint_catalog=endpoint_catalog,
            endpoint_flows=endpoint_flows,
            component_flows=component_flows,
            insights=insights,
        )

        if endpoint_truncated and "flow_truncated" not in truncated_flags:
            truncated_flags.append("flow_truncated")
        truncation_reasons = sorted(set(truncated_flags))
        return {
            "architecture_overview": architecture_overview,
            "endpoint_catalog": endpoint_catalog,
            "endpoint_flows": endpoint_flows,
            "function_dependency_index": dependency_index,
            "component_flows": component_flows,
            "narrative_sections": narrative_sections,
            "truncated": bool(endpoint_truncated or truncation_reasons),
            "truncation_reasons": truncation_reasons,
            "limits": {
                "max_nodes_per_flow": self.caps.max_nodes_per_flow,
                "max_depth": self.caps.max_depth,
                "max_endpoint_flows": self.caps.max_endpoint_flows,
                "max_component_flows": self.caps.max_component_flows,
            },
        }

    def _traverse_flow(
        self,
        *,
        start_id: str,
        adjacency_out: dict[str, list[dict[str, Any]]],
        node_by_id: dict[str, dict[str, Any]],
        include_edge_types: set[str],
    ) -> dict[str, Any]:
        visited: set[str] = set()
        order: list[str] = []
        queue: deque[tuple[str, int]] = deque([(start_id, 0)])
        truncated = False
        cycle_detected = False

        while queue:
            node_id, depth = queue.popleft()
            if node_id in visited:
                cycle_detected = True
                continue
            visited.add(node_id)
            order.append(node_id)
            if len(order) >= self.caps.max_nodes_per_flow:
                truncated = True
                break
            if depth >= self.caps.max_depth:
                truncated = True
                continue
            outgoing = list(adjacency_out.get(node_id, []))
            for edge in outgoing:
                if str(edge.get("type", "")) not in include_edge_types:
                    continue
                nxt = str(edge.get("to", ""))
                if not nxt:
                    continue
                if nxt in visited:
                    cycle_detected = True
                    continue
                queue.append((nxt, depth + 1))

        reachable_nodes = []
        for node_id in order:
            node = node_by_id.get(node_id, {})
            reachable_nodes.append(
                {
                    "id": node_id,
                    "type": str(node.get("type", "")),
                    "label": str(node.get("label", "")),
                    "file": str(node.get("file", "")),
                },
            )
        return {
            "start_id": start_id,
            "depth": len(order),
            "reachable_node_ids": order,
            "reachable_nodes": reachable_nodes,
            "truncated": truncated,
            "cycle_detected": cycle_detected,
        }

    def _build_narrative_sections(
        self,
        *,
        architecture_overview: dict[str, Any],
        endpoint_catalog: list[dict[str, Any]],
        endpoint_flows: list[dict[str, Any]],
        component_flows: list[dict[str, Any]],
        insights: dict[str, Any],
    ) -> list[dict[str, str]]:
        backend = architecture_overview.get("backend", {})
        frontend = architecture_overview.get("frontend", {})
        get_count = sum(1 for r in endpoint_catalog if str(r.get("method", "")).upper() == "GET")
        post_count = sum(1 for r in endpoint_catalog if str(r.get("method", "")).upper() == "POST")
        put_count = sum(1 for r in endpoint_catalog if str(r.get("method", "")).upper() in {"PUT", "PATCH"})
        delete_count = sum(1 for r in endpoint_catalog if str(r.get("method", "")).upper() == "DELETE")

        deepest = sorted(endpoint_flows, key=lambda item: int(item.get("depth", 0)), reverse=True)
        deep_preview = ""
        if deepest:
            top = deepest[0]
            deep_preview = (
                f"Deepest endpoint flow currently reaches depth {int(top.get('depth', 0))} "
                f"from {top.get('method', '')} {top.get('uri', '')}."
            )
        dead = insights.get("dead_code", {})
        dead_summary = (
            f"Potentially unused: {len(dead.get('methods', []) or [])} methods, "
            f"{len(dead.get('controllers', []) or [])} controllers, "
            f"{len(dead.get('components', []) or [])} components."
        )
        coupling_count = len((insights.get("coupling", {}) or {}).get("high_coupling", []) or [])
        god_count = len(insights.get("god_classes", []) or [])

        return [
            {
                "title": "How This Project Is Structured",
                "body": (
                    f"Backend map includes {backend.get('routes', 0)} routes, "
                    f"{backend.get('controllers', 0)} controllers, {backend.get('services', 0)} services, "
                    f"and {backend.get('models', 0)} models. Frontend map includes "
                    f"{frontend.get('pages', 0)} pages, {frontend.get('components', 0)} components, "
                    f"and {frontend.get('hooks', 0)} hooks."
                ),
            },
            {
                "title": "API Flows (GET/POST/...)",
                "body": (
                    f"Detected endpoints: GET={get_count}, POST={post_count}, PUT/PATCH={put_count}, DELETE={delete_count}. "
                    f"{deep_preview}".strip()
                ),
            },
            {
                "title": "What Depends On What",
                "body": (
                    f"High-coupling classes detected: {coupling_count}. "
                    f"Large class candidates: {god_count}. {dead_summary}"
                ),
            },
            {
                "title": "Execution Flow Trace",
                "body": (
                    "Flow traces are static and transitive with cycle guards. "
                    "If truncation is reported, increase limits or inspect the focused subgraph."
                ),
            },
            {
                "title": "Component Flow",
                "body": (
                    f"Component traversal built {len(component_flows)} entry flows from pages/components with hook/import relations."
                ),
            },
        ]

    def _build_explainer_summary(self, explainer: dict[str, Any]) -> dict[str, Any]:
        overview = dict(explainer.get("architecture_overview") or {})
        endpoint_catalog = list(explainer.get("endpoint_catalog") or [])
        endpoint_flows = list(explainer.get("endpoint_flows") or [])
        narrative = list(explainer.get("narrative_sections") or [])
        return {
            "architecture_overview": overview,
            "endpoint_count": len(endpoint_catalog),
            "endpoint_flow_count": len(endpoint_flows),
            "component_flow_count": len(list(explainer.get("component_flows") or [])),
            "truncated": bool(explainer.get("truncated", False)),
            "truncation_reasons": list(explainer.get("truncation_reasons", []) or []),
            "narrative_sections": narrative[:3],
        }


def build_minimal_artifact_from_report(report: ScanReport) -> dict[str, Any]:
    """
    Conservative fallback artifact when map artifact is unavailable for a completed report.

    This keeps API responses deterministic/non-breaking even if reporting enrichment failed.
    """
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    file_node_map: dict[str, str] = {}
    rule_node_map: dict[str, str] = {}
    for f in list(getattr(report, "findings", []) or []):
        file_path = _normalized_path(str(getattr(f, "file", "") or ""))
        rule_id = str(getattr(f, "rule_id", "") or "")
        if not file_path or not rule_id:
            continue
        if file_path not in file_node_map:
            nid = f"file:{file_path}"
            file_node_map[file_path] = nid
            nodes.append({"id": nid, "type": "file", "label": file_path.split("/")[-1], "file": file_path, "metadata": {}})
        if rule_id not in rule_node_map:
            rid = f"rule:{rule_id}"
            rule_node_map[rule_id] = rid
            nodes.append({"id": rid, "type": "rule", "label": rule_id, "file": "", "metadata": {}})
        edges.append({"from": rule_node_map[rule_id], "to": file_node_map[file_path], "type": "flags", "metadata": {}})

    summary = {
        "architecture_overview": {
            "backend": {"routes": 0, "controllers": 0, "services": 0, "models": 0},
            "frontend": {"pages": 0, "components": 0, "hooks": 0},
        },
        "endpoint_count": 0,
        "endpoint_flow_count": 0,
        "component_flow_count": 0,
        "truncated": False,
        "truncation_reasons": [],
        "narrative_sections": [
            {
                "title": "Fallback Map",
                "body": "Project map artifact was unavailable for this scan; showing finding-to-file fallback graph.",
            },
        ],
    }

    return {
        "nodes": nodes,
        "edges": edges,
        "hierarchy": {"backend": {}, "frontend": {}, "summary": {}},
        "insights": {"warnings": []},
        "explainer": {
            "architecture_overview": summary["architecture_overview"],
            "endpoint_catalog": [],
            "endpoint_flows": [],
            "function_dependency_index": {},
            "component_flows": [],
            "narrative_sections": summary["narrative_sections"],
            "truncated": False,
            "truncation_reasons": [],
            "limits": {},
        },
        "explainer_summary": summary,
        "meta": {
            "version": 1,
            "scan_id": report.id,
            "project_hash": _stable_short_hash(str(Path(report.project_path).resolve()), length=16),
            "generated_at": _now_iso(),
            "signature": "fallback",
            "truncated": False,
            "truncation_reasons": [],
            "cache_hit": False,
            "counts": {"nodes": len(nodes), "edges": len(edges)},
            "fallback": True,
        },
    }


def filter_explainer_payload(
    artifact: dict[str, Any],
    *,
    entry_type: str | None = None,
    entry_id: str | None = None,
    framework: str | None = None,
    problems_only: bool = False,
    include_reverse: bool = False,
) -> dict[str, Any]:
    """Return filtered deep explainer payload for dedicated endpoint usage."""
    explainer = deepcopy(dict(artifact.get("explainer") or {}))
    insights = dict(artifact.get("insights") or {})
    warnings = list(insights.get("warnings") or [])
    warning_node_ids = {str(w.get("node_id", "")) for w in warnings if str(w.get("node_id", ""))}

    fw = str(framework or "").strip().lower()
    if fw:
        if fw in {"laravel", "backend", "php"}:
            explainer["component_flows"] = []
            explainer["endpoint_catalog"] = [
                e for e in list(explainer.get("endpoint_catalog") or []) if str(e.get("framework", "laravel")).lower() == "laravel"
            ]
            explainer["endpoint_flows"] = [
                e for e in list(explainer.get("endpoint_flows") or []) if str(e.get("framework", "laravel")).lower() == "laravel"
            ]
        elif fw in {"react", "frontend"}:
            explainer["endpoint_catalog"] = []
            explainer["endpoint_flows"] = []
            explainer["component_flows"] = [
                e for e in list(explainer.get("component_flows") or []) if str(e.get("framework", "react")).lower() == "react"
            ]

    entry_type_norm = str(entry_type or "").strip().lower()
    entry_id_norm = str(entry_id or "").strip()
    if entry_type_norm and entry_id_norm:
        if entry_type_norm in {"endpoint", "route"}:
            explainer["endpoint_catalog"] = [
                e for e in list(explainer.get("endpoint_catalog") or []) if str(e.get("entry_id", "")) == entry_id_norm
            ]
            explainer["endpoint_flows"] = [
                e for e in list(explainer.get("endpoint_flows") or []) if str(e.get("entry_id", "")) == entry_id_norm
            ]
        elif entry_type_norm in {"component", "page"}:
            explainer["component_flows"] = [
                e
                for e in list(explainer.get("component_flows") or [])
                if str(e.get("entry_id", "")) == entry_id_norm or str(e.get("start_id", "")) == entry_id_norm
            ]
        elif entry_type_norm in {"function", "method", "service", "class", "node"}:
            dep = dict(explainer.get("function_dependency_index") or {})
            if entry_id_norm in dep:
                explainer["function_dependency_index"] = {entry_id_norm: dep[entry_id_norm]}
            else:
                # Label-based fallback.
                filtered_dep = {
                    k: v
                    for k, v in dep.items()
                    if entry_id_norm.lower() in str(v.get("label", "")).lower()
                }
                explainer["function_dependency_index"] = filtered_dep

    if problems_only:
        flow_like_keys = ("endpoint_flows", "component_flows")
        for key in flow_like_keys:
            filtered = []
            for flow in list(explainer.get(key) or []):
                node_ids = set(flow.get("reachable_node_ids") or [])
                start_id = str(flow.get("start_id", "") or flow.get("entry_id", ""))
                if start_id:
                    node_ids.add(start_id)
                if node_ids.intersection(warning_node_ids):
                    filtered.append(flow)
            explainer[key] = filtered

        dep = dict(explainer.get("function_dependency_index") or {})
        explainer["function_dependency_index"] = {
            node_id: data for node_id, data in dep.items() if node_id in warning_node_ids
        }

    if not include_reverse:
        dep = dict(explainer.get("function_dependency_index") or {})
        for key, value in dep.items():
            if isinstance(value, dict):
                value["called_by"] = []
                value["used_by"] = []
            dep[key] = value
        explainer["function_dependency_index"] = dep

    return {
        "explainer": explainer,
        "filters": {
            "entry_type": entry_type_norm or None,
            "entry_id": entry_id_norm or None,
            "framework": fw or None,
            "problems_only": bool(problems_only),
            "include_reverse": bool(include_reverse),
        },
        "meta": dict(artifact.get("meta") or {}),
    }
