"""Fast, deterministic project file inventory shared by scan stages."""

from __future__ import annotations

import os
from pathlib import Path

from core.path_utils import normalize_rel_path


DEFAULT_SKIPPED_DIR_NAMES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".idea",
        ".vscode",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        "vendor",
        "bower_components",
        "dist",
        "build",
        "coverage",
        "storage",
        ".next",
        ".nuxt",
        ".output",
        ".turbo",
        ".pnpm-store",
        ".yarn",
    },
)


def discover_project_files(
    project_root: str | Path,
    *,
    skipped_dir_names: set[str] | frozenset[str] = DEFAULT_SKIPPED_DIR_NAMES,
    max_files: int = 200_000,
) -> list[str]:
    """Return a sorted relative-path inventory using one pruned filesystem walk.

    This deliberately applies only universally safe generated/vendor directory
    exclusions. Ruleset-specific ignore patterns are applied later by the facts
    builder, so a custom project layout is not lost during discovery.
    """

    root = Path(project_root).resolve()
    if not root.is_dir():
        return []

    skipped = {str(name or "").strip().lower() for name in skipped_dir_names if name}
    found: list[str] = []
    try:
        for current_root, dirs, files in os.walk(str(root), topdown=True):
            current = Path(current_root)
            try:
                rel_current = normalize_rel_path(str(current.relative_to(root))).strip("/")
            except ValueError:
                rel_current = ""
            dirs[:] = sorted(
                (
                    dirname
                    for dirname in dirs
                    if dirname.lower() not in skipped
                    and not _is_generated_relative_dir(
                        "/".join(part for part in (rel_current, dirname) if part),
                    )
                ),
                key=str.lower,
            )
            for filename in sorted(files, key=str.lower):
                path = current / filename
                try:
                    rel_path = normalize_rel_path(str(path.relative_to(root)))
                except (OSError, ValueError):
                    continue
                if rel_path:
                    found.append(rel_path)
                    if max_files > 0 and len(found) >= max_files:
                        return sorted(found)
    except OSError:
        return sorted(found)
    return sorted(found)


def _is_generated_relative_dir(rel_path: str) -> bool:
    normalized = "/" + normalize_rel_path(rel_path).lower().strip("/")
    return any(
        normalized.endswith(suffix) or f"{suffix}/" in normalized
        for suffix in ("/bootstrap/cache", "/public/build", "/public/dist/assets")
    )


def inventory_paths(project_root: str | Path, relative_paths: list[str]) -> list[tuple[str, Path]]:
    """Resolve inventory paths safely beneath ``project_root``."""

    root = Path(project_root).resolve()
    resolved: list[tuple[str, Path]] = []
    for raw_path in relative_paths:
        rel_path = normalize_rel_path(str(raw_path or "")).strip("/")
        if not rel_path:
            continue
        candidate = (root / Path(rel_path)).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            continue
        resolved.append((rel_path, candidate))
    return resolved
