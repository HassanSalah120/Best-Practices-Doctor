"""Shared semantic file-role inference for analyzer rules.

Rules should prefer these project facts and source signals over spelling a
framework's default directory layout themselves.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path, PurePosixPath
import re

from core.path_utils import normalize_rel_path
from schemas.facts import Facts


_REACT_EXTENSIONS = (".js", ".jsx", ".ts", ".tsx")
_PAGE_PATH_MARKERS = ("/pages/", "/page/", "/screens/", "/screen/", "/views/", "/view/", "/routes/")


def normalized_path(file_path: str) -> str:
    return normalize_rel_path(str(file_path or "")).lower()


def files_for_fact_bucket(facts: Facts, bucket: str) -> set[str]:
    return {
        normalized_path(str(getattr(item, "file_path", "") or ""))
        for item in (getattr(facts, bucket, []) or [])
        if str(getattr(item, "file_path", "") or "")
    }


def is_job_source(file_path: str, content: str, facts: Facts) -> bool:
    path = normalized_path(file_path)
    if path in files_for_fact_bucket(facts, "jobs"):
        return True
    text = content or ""
    return bool(
        re.search(r"\bimplements\b[^\{;]*\bShouldQueue\b", text, re.IGNORECASE | re.DOTALL)
        or re.search(r"\bShouldQueue\b", text) and re.search(r"\bfunction\s+handle\s*\(", text, re.IGNORECASE)
    )


def is_controller_source(file_path: str, content: str, facts: Facts) -> bool:
    path = normalized_path(file_path)
    if path in files_for_fact_bucket(facts, "controllers"):
        return True
    return bool(re.search(r"\bclass\s+\w+\s+extends\s+[^\{;]*Controller\b", content or "", re.IGNORECASE))


def is_service_source(file_path: str, content: str, facts: Facts) -> bool:
    path = normalized_path(file_path)
    if path in files_for_fact_bucket(facts, "services"):
        return True
    return bool(re.search(r"\bclass\s+\w+(?:Service|Handler|Action|Command|Query)\b", content or ""))


def is_inertia_react_project(facts: Facts, content: str = "") -> bool:
    if "@inertiajs/react" in (content or ""):
        return True
    technical_type = str(getattr(facts, "framework_project_type", "") or "").lower()
    if "inertia_react" in technical_type:
        return True
    for component in getattr(facts, "react_components", []) or []:
        if any("@inertiajs/react" in str(item or "").lower() for item in (getattr(component, "imports", []) or [])):
            return True
    graph = getattr(facts, "_frontend_symbol_graph", None)
    if isinstance(graph, dict):
        for payload in (graph.get("files", {}) or {}).values():
            if isinstance(payload, dict) and any(
                "@inertiajs/react" in str(item or "").lower()
                for item in (payload.get("imports", []) or [])
            ):
                return True
    return False


def is_react_page_source(file_path: str, content: str, facts: Facts) -> bool:
    """Identify route/page components using project wiring plus code signals."""

    path = normalized_path(file_path)
    text = content or ""
    component_names = {
        str(getattr(component, "name", "") or "")
        for component in (getattr(facts, "react_components", []) or [])
        if normalized_path(str(getattr(component, "file_path", "") or "")) == path
    }
    if any(name.endswith(("Page", "Screen", "View")) for name in component_names):
        return True
    if any(marker in f"/{path}" for marker in _PAGE_PATH_MARKERS):
        return True
    if re.search(r"\b(?:usePage|useForm)\s*\(", text) and re.search(r"\bexport\s+default\b", text):
        return True
    if path in _inertia_page_files(facts):
        return True
    return False


def is_blade_component_source(file_path: str, content: str, facts: Facts) -> bool:
    path = normalized_path(file_path)
    text = content or ""
    if not path.endswith(".blade.php") or "$slot" not in text:
        return False
    if re.search(r"<\s*html\b", text, re.IGNORECASE):
        return False
    if "/components/" in f"/{path}":
        return True
    # Anonymous components are fundamentally identified by slot semantics;
    # projects may register additional anonymous component namespaces.
    return bool(re.search(r"\$slot(?:\b|->)|\{\{\s*\$slot\s*\}\}", text))


def is_api_route(route) -> bool:
    uri = str(getattr(route, "uri", "") or "").strip("/").lower()
    middleware = " ".join(str(item or "").lower() for item in (getattr(route, "middleware", []) or []))
    path = normalized_path(str(getattr(route, "file_path", "") or ""))
    return uri == "api" or uri.startswith("api/") or "api" in middleware.split() or "/api/" in f"/{path}"


def _inertia_page_files(facts: Facts) -> set[str]:
    project_path = str(getattr(facts, "project_path", "") or "")
    candidates = tuple(
        sorted(
            normalized_path(str(path or ""))
            for path in (getattr(facts, "files", []) or [])
            if normalized_path(str(path or "")).endswith(_REACT_EXTENSIONS)
        )
    )
    hashes = getattr(facts, "file_hashes", {}) or {}
    signature = tuple((path, str(hashes.get(path, "") or "")) for path in candidates)
    return set(_inertia_page_files_cached(project_path, signature))


@lru_cache(maxsize=64)
def _inertia_page_files_cached(project_path: str, signature: tuple[tuple[str, str], ...]) -> tuple[str, ...]:
    root = Path(project_path)
    files = [path for path, _ in signature]
    page_roots: set[str] = set()
    glob_pattern = re.compile(r"import\.meta\.glob\s*\(\s*['\"](?P<glob>[^'\"]+)['\"]")
    for rel_path in files:
        try:
            source = (root / rel_path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "createInertiaApp" not in source and "resolvePageComponent" not in source:
            continue
        parent = PurePosixPath(rel_path).parent
        for match in glob_pattern.finditer(source):
            raw = match.group("glob").replace("\\", "/")
            prefix = raw.split("*")[0].rstrip("/")
            resolved = str(parent.joinpath(prefix)).replace("\\", "/")
            page_roots.add(normalized_path(resolved).rstrip("/"))
    return tuple(
        path
        for path in files
        if any(path == page_root or path.startswith(page_root + "/") for page_root in page_roots)
    )
