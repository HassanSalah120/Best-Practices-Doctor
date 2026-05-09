"""
Shared test scaffold and test file detection helpers.
"""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath

from core.path_utils import normalize_rel_path

TEST_FILE_EXTENSIONS = {
    ".php",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".vue",
}

TEST_CONFIG_FILES = {
    "phpunit.xml",
    "phpunit.xml.dist",
    "pest.php",
    "jest.config.js",
    "jest.config.cjs",
    "jest.config.mjs",
    "jest.config.ts",
    "jest.config.json",
    "vitest.config.js",
    "vitest.config.cjs",
    "vitest.config.mjs",
    "vitest.config.ts",
    "vitest.config.mts",
    "playwright.config.js",
    "playwright.config.ts",
    "cypress.config.js",
    "cypress.config.ts",
}

SKIP_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    ".output",
    ".turbo",
    ".pnpm-store",
    ".yarn",
    "public/build",
    "bootstrap/cache",
    "storage",
}

TEST_DIR_NAMES = {"tests", "test", "__tests__", "cypress", "e2e", "playwright"}
TEST_FILE_MARKERS = (".test.", ".spec.", ".cy.")
TEST_PREFIXES = ("test_",)
TEST_SUFFIXES = ("test.php", "test.ts", "test.tsx", "test.js", "test.jsx")


def iter_project_files(project_root: Path):
    """Iterate project files while skipping well-known generated/vendor folders."""
    root = Path(project_root).resolve()
    for current_root, dirs, files in os.walk(str(root)):
        current = Path(current_root)
        rel_current = normalize_rel_path(str(current.relative_to(root))) if current != root else ""

        filtered_dirs: list[str] = []
        for dirname in dirs:
            rel_dir = normalize_rel_path("/".join(part for part in [rel_current, dirname] if part))
            rel_dir_low = rel_dir.lower()
            if rel_dir_low in SKIP_DIRS:
                continue
            if any(rel_dir_low.startswith(prefix + "/") for prefix in SKIP_DIRS if "/" in prefix):
                continue
            filtered_dirs.append(dirname)
        dirs[:] = filtered_dirs

        for filename in files:
            path = current / filename
            try:
                rel_path = normalize_rel_path(str(path.relative_to(root)))
            except Exception:
                continue
            if rel_path:
                yield rel_path, path


def is_test_like_path(rel_path: str) -> bool:
    """Return True when a relative path looks like a real test file."""
    norm = normalize_rel_path(rel_path).lower()
    if not norm:
        return False

    pure = PurePosixPath(norm)
    parts = pure.parts
    name = pure.name
    suffix = pure.suffix.lower()

    if name in TEST_CONFIG_FILES:
        return True

    if suffix not in TEST_FILE_EXTENSIONS:
        return False

    if any(part in TEST_DIR_NAMES for part in parts):
        return True
    if any(marker in name for marker in TEST_FILE_MARKERS):
        return True
    if name.startswith(TEST_PREFIXES):
        return True
    if name.endswith(TEST_SUFFIXES):
        return True

    return False


def has_test_scaffold(project_root: str | Path) -> bool:
    """Return True when a project contains a recognizable automated test scaffold."""
    root = Path(project_root).resolve()
    for rel_path, _ in iter_project_files(root):
        if is_test_like_path(rel_path):
            return True
    return False


def count_test_files(project_root: str | Path, cap: int = 10_000) -> int:
    """Count detected test files across backend and frontend conventions."""
    root = Path(project_root).resolve()
    count = 0
    for rel_path, path in iter_project_files(root):
        name = path.name.lower()
        if name in TEST_CONFIG_FILES:
            continue
        if is_test_like_path(rel_path):
            count += 1
            if count >= cap:
                return count
    return count
