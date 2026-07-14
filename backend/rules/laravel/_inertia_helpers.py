"""Shared helpers for Inertia-related rules."""

import contextlib
import json
import os
import re
from pathlib import Path

from schemas.facts import Facts, MethodInfo, RouteInfo

_INERTIA_RENDER = re.compile(r"Inertia::render\s*\(", re.IGNORECASE)


def is_inertia_project(facts: Facts, file_path: str | None = None) -> bool:
    """
    Returns True if the project appears to use Inertia.js.
    Checks:
    1. Facts project_type indicates Inertia
    2. composer.json contains inertiajs/inertia-laravel
    3. package.json contains @inertiajs/react or @inertiajs/vue
    4. Any scanned file contains Inertia::render(
    """
    if facts and facts.project_context:
        project_type = (facts.project_context.project_type or "").strip().lower()
        if project_type in ("laravel_inertia_react", "laravel_inertia_vue"):
            return True

    project_path = (facts.project_path if facts else "") or "."

    composer_path = os.path.join(project_path, "composer.json")
    if os.path.isfile(composer_path):
        try:
            with open(composer_path, encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            for section in ("require", "require-dev"):
                deps = data.get(section, {})
                if "inertiajs/inertia-laravel" in deps:
                    return True
        except Exception:
            pass

    for pkg_file in ("package.json", "frontend/package.json", "resources/js/package.json"):
        pkg_path = os.path.join(project_path, pkg_file)
        if os.path.isfile(pkg_path):
            try:
                with open(pkg_path, encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                for section in ("dependencies", "devDependencies"):
                    deps = data.get(section, {})
                    if any(pkg in deps for pkg in ("@inertiajs/react", "@inertiajs/vue")):
                        return True
            except Exception:
                pass

    if file_path and _INERTIA_RENDER.search(open(file_path, encoding="utf-8", errors="ignore").read()):
        return True

    return False


def extract_method_source(content: str, line_start: int, line_end: int) -> str:
    """
    Extract method source from full file content using line boundaries.
    line_start and line_end are 1-indexed (matching MethodInfo).
    """
    lines = content.split("\n")
    start = max(0, line_start - 1)
    end = min(len(lines), line_end)
    return "\n".join(lines[start:end])


def read_method_source(facts: Facts, method: MethodInfo) -> str:
    """Read a method body from either a project-relative or absolute fact path."""
    raw_path = str(method.file_path or "").strip()
    if not raw_path:
        return ""

    path = Path(raw_path)
    if not path.is_absolute():
        path = Path(str(getattr(facts, "project_path", "") or ".")) / path
    try:
        content = path.resolve().read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""
    return extract_method_source(content, method.line_start, method.line_end)


def route_targets_controller_file(route: RouteInfo, controller_file: str, facts: Facts) -> bool:
    """Return True when a route handler resolves to the current controller file.

    Route declarations often use imported short names like `InventoryController::class`.
    Matching only by basename makes `Api\\InventoryController` collide with
    `Clinic\\InventoryController`. Prefer import/class facts and fall back to
    basename matching only when that class name is unique in the project.
    """
    route_controller = str(route.controller or "").strip().strip("\\")
    if not route_controller:
        return False

    normalized_file = _normalize_path(controller_file)
    class_infos = list(getattr(facts, "classes", []) or [])
    current_classes = [
        cls for cls in class_infos
        if _same_path(_normalize_path(str(getattr(cls, "file_path", "") or "")), normalized_file)
    ]
    if not current_classes:
        # No class facts available — fall back to basename matching
        # between the route's controller name and the file name.
        route_basename = route_controller.split("\\")[-1].lower()
        file_basename = normalized_file.rsplit("/", 1)[-1].rsplit(".", 1)[0].lower()
        if route_basename == file_basename or file_basename.endswith(route_basename):
            return True
        return False

    route_fqcn = _resolve_route_controller_fqcn(route, facts)
    if route_fqcn:
        route_fqcn_low = route_fqcn.lower().strip("\\")
        return any(str(getattr(cls, "fqcn", "") or "").lower().strip("\\") == route_fqcn_low for cls in current_classes)

    route_basename = route_controller.split("\\")[-1].lower()
    matching_classes = [
        cls for cls in class_infos
        if str(getattr(cls, "name", "") or "").lower() == route_basename
    ]
    if len(matching_classes) == 1:
        return _same_path(_normalize_path(str(getattr(matching_classes[0], "file_path", "") or "")), normalized_file)

    return False


def is_api_route(route: RouteInfo) -> bool:
    route_file = _normalize_path(str(route.file_path or ""))
    uri = str(route.uri or "").strip("/").lower()
    # Match routes defined under any file containing "api" in a route directory.
    if "routes/" in route_file and "api" in route_file.lower():
        return True
    return uri == "api" or uri.startswith("api/")


def is_web_route(route: RouteInfo) -> bool:
    route_file = _normalize_path(str(route.file_path or ""))
    if "routes/" in route_file and "api" in route_file.lower():
        return False
    if "routes/" in route_file:
        return True
    uri = str(route.uri or "").strip("/").lower()
    return not (uri == "api" or uri.startswith("api/"))


def _resolve_route_controller_fqcn(route: RouteInfo, facts: Facts) -> str:
    controller = str(route.controller or "").strip().strip("\\")
    if not controller:
        return ""
    if "\\" in controller:
        return controller

    route_file = _normalize_path(str(route.file_path or ""))
    alias = controller.split("\\")[-1]
    alias_low = alias.lower()
    for item in getattr(facts, "use_imports", []) or []:
        if not _same_path(_normalize_path(str(getattr(item, "file_path", "") or "")), route_file):
            continue
        import_alias = str(getattr(item, "alias", "") or "").strip() or str(getattr(item, "fqcn", "") or "").split("\\")[-1]
        if import_alias.lower() == alias_low:
            return str(getattr(item, "fqcn", "") or "").strip("\\")

    return ""


def _normalize_path(path: str) -> str:
    normalized = (path or "").replace("\\", "/").lower()
    with contextlib.suppress(Exception):
        return os.path.normpath(path).replace("\\", "/").lower()
    return normalized


def _same_path(left: str, right: str) -> bool:
    left_norm = (left or "").strip("/")
    right_norm = (right or "").strip("/")
    return (
        left_norm == right_norm
        or left_norm.endswith(f"/{right_norm}")
        or right_norm.endswith(f"/{left_norm}")
    )
