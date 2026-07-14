"""Project-level React error-boundary discovery helpers."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path, PurePosixPath
import re

from schemas.facts import Facts


_SOURCE_EXTENSIONS = (".tsx", ".jsx", ".ts", ".js")
_IGNORED_MARKERS = ("/node_modules/", "/vendor/", "/dist/", "/build/", "/coverage/")
_ROOT_RENDER = re.compile(
    r"\b(?:createRoot\s*\(.{0,500}?\)\s*\.\s*render|hydrateRoot)\s*\(",
    re.IGNORECASE | re.DOTALL,
)
_BOUNDARY_ROOT_RETURN = re.compile(
    r"(?:\breturn\s*\(|=>\s*\(?)\s*<\s*ErrorBoundary\b",
    re.IGNORECASE | re.DOTALL,
)
_IMPORT = re.compile(
    r"\bimport\s+(?P<binding>[A-Za-z_$][\w$]*)\s+from\s+['\"](?P<specifier>\.[^'\"]+)['\"]",
)
_JSX_SYMBOL = re.compile(r"<\s*([A-Z][A-Za-z0-9_$]*)\b")


def global_error_boundary_file(facts: Facts) -> str | None:
    """Return the boundary-owning root module when all rendered pages are protected.

    Discovery starts at a semantic React root-render call and follows local default
    component imports, so it does not assume names such as ``main.tsx`` or ``App.tsx``.
    """

    project_path = str(getattr(facts, "project_path", "") or "")
    candidates: list[tuple[str, str]] = []
    hashes = getattr(facts, "file_hashes", {}) or {}
    for raw_path in getattr(facts, "files", []) or []:
        normalized = str(raw_path or "").replace("\\", "/")
        lowered = f"/{normalized.lower().lstrip('/')}"
        if not lowered.endswith(_SOURCE_EXTENSIONS) or any(marker in lowered for marker in _IGNORED_MARKERS):
            continue
        candidates.append((normalized, str(hashes.get(raw_path, hashes.get(normalized, "")) or "")))

    return _global_error_boundary_file_cached(project_path, tuple(sorted(candidates)))


@lru_cache(maxsize=64)
def _global_error_boundary_file_cached(
    project_path: str,
    candidates: tuple[tuple[str, str], ...],
) -> str | None:
    root = Path(project_path)
    sources: dict[str, str] = {}
    canonical_paths: dict[str, str] = {}

    for relative_path, _file_hash in candidates:
        try:
            source = (root / Path(relative_path)).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        normalized = relative_path.replace("\\", "/")
        sources[normalized] = source
        canonical_paths[_module_key(normalized)] = normalized

    for entry_path, source in sources.items():
        if not _ROOT_RENDER.search(source):
            continue
        boundary_path = _boundary_on_root_render_chain(entry_path, sources, canonical_paths)
        if boundary_path:
            return boundary_path
    return None


def _boundary_on_root_render_chain(
    entry_path: str,
    sources: dict[str, str],
    canonical_paths: dict[str, str],
) -> str | None:
    pending = [entry_path]
    visited: set[str] = set()

    while pending:
        current_path = pending.pop()
        if current_path in visited:
            continue
        visited.add(current_path)
        source = sources.get(current_path, "")

        if _renders_boundary_at_root(source):
            return current_path

        imports = {match.group("binding"): match.group("specifier") for match in _IMPORT.finditer(source)}
        for symbol in _JSX_SYMBOL.findall(source):
            specifier = imports.get(symbol)
            if not specifier:
                continue
            resolved = _resolve_local_import(current_path, specifier, canonical_paths)
            if resolved and resolved not in visited:
                pending.append(resolved)
    return None


def _renders_boundary_at_root(source: str) -> bool:
    if not re.search(r"<\s*ErrorBoundary\b", source):
        return False
    root_render = _ROOT_RENDER.search(source)
    if root_render:
        render_tail = source[root_render.end() :]
        # Providers and StrictMode may legitimately sit outside the boundary.
        if re.search(r"<\s*ErrorBoundary\b", render_tail[:3000], re.IGNORECASE | re.DOTALL):
            return True
    return bool(_BOUNDARY_ROOT_RETURN.search(source))


def _resolve_local_import(
    importer_path: str,
    specifier: str,
    canonical_paths: dict[str, str],
) -> str | None:
    parent = PurePosixPath(importer_path).parent
    joined = str(parent.joinpath(specifier)).replace("\\", "/")
    key = _module_key(joined)
    if key in canonical_paths:
        return canonical_paths[key]
    return canonical_paths.get(f"{key}/index")


def _module_key(path: str) -> str:
    normalized = str(PurePosixPath(path.replace("\\", "/")))
    for extension in _SOURCE_EXTENSIONS:
        if normalized.lower().endswith(extension):
            return normalized[: -len(extension)]
    return normalized
