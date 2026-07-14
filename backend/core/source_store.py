"""Indexed, safe, scan-scoped source access for file-based rules."""

from __future__ import annotations

import threading
from collections import defaultdict
from pathlib import Path

from core.path_utils import normalize_rel_path


def normalize_extensions(raw_extensions: object, defaults: tuple[str, ...]) -> set[str]:
    values = raw_extensions or defaults
    if isinstance(values, str):
        values = (values,)
    normalized: set[str] = set()
    for raw in values:
        extension = str(raw or "").strip().lower()
        if not extension:
            continue
        normalized.add(extension if extension.startswith(".") else f".{extension}")
    return normalized or set(defaults)


class SourceFileStore:
    """Read each source once and pre-index candidates by extension."""

    def __init__(self, project_path: str, files: list[str], test_files: list[str] | None = None):
        self.root = Path(project_path or ".").resolve()
        self._files = self._dedupe(files)
        self._test_files = self._dedupe(test_files or [])
        self._cache: dict[str, str] = {}
        self._lock = threading.RLock()
        self._by_suffix: dict[str, list[str]] = defaultdict(list)
        for rel_path in self._dedupe([*self._files, *self._test_files]):
            lower = rel_path.lower()
            suffix = Path(lower).suffix
            if suffix:
                self._by_suffix[suffix].append(rel_path)
        self._stats = {
            "candidate_files": len(self._files),
            "candidate_test_files": len(self._test_files),
            "disk_reads": 0,
            "cache_hits": 0,
            "read_failures": 0,
            "bytes_read": 0,
        }

    @staticmethod
    def _dedupe(paths: list[str]) -> list[str]:
        return list(
            dict.fromkeys(
                rel
                for raw in paths
                if (rel := normalize_rel_path(str(raw or "")).strip("/"))
            ),
        )

    def paths_for_extensions(self, extensions: set[str], *, include_tests: bool = False) -> list[str]:
        allowed = {str(ext or "").lower() for ext in extensions if ext}
        pool = [*self._files, *self._test_files] if include_tests else self._files
        # The suffix index handles normal extensions in O(matches). Fall back
        # to endswith for compound/custom extensions.
        if all(ext.count(".") == 1 for ext in allowed):
            eligible = {path for ext in allowed for path in self._by_suffix.get(ext, [])}
            return [path for path in pool if path in eligible]
        return [path for path in pool if any(path.lower().endswith(ext) for ext in allowed)]

    def read(self, rel_path: str) -> str:
        normalized = normalize_rel_path(str(rel_path or "")).strip("/")
        if not normalized:
            return ""
        with self._lock:
            if normalized in self._cache:
                self._stats["cache_hits"] += 1
                return self._cache[normalized]
        candidate = (self.root / Path(normalized)).resolve()
        try:
            candidate.relative_to(self.root)
            text = candidate.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            text = ""
            with self._lock:
                self._stats["read_failures"] += 1
        with self._lock:
            self._cache[normalized] = text
            if text:
                self._stats["disk_reads"] += 1
                self._stats["bytes_read"] += len(text.encode("utf-8", errors="replace"))
        return text

    def stats(self) -> dict[str, int]:
        with self._lock:
            return dict(self._stats)
