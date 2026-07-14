"""Persistent stage-output cache for scan pipeline."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import pickle
import threading
import time
from pathlib import Path
from typing import Any

_STAGE_VERSIONS = {
    "detect_project": 2,
    "build_facts": 2,
    "run_rules": 2,
    "scoring": 2,
}

_DEFAULT_EXCLUDES = {
    ".git",
    "node_modules",
    "vendor",
    ".idea",
    ".vscode",
    "storage",
    "bootstrap/cache",
    ".bpdoctor",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".cache",
    "coverage",
}


class StageCacheManager:
    """Simple persistent cache keyed by stage + project/request signatures."""

    CACHE_DIR = "pipeline_stage_cache"

    def __init__(self, project_path: str):
        self.project_path = str(project_path or "")
        app_data = os.environ.get("BPD_APP_DATA_DIR")
        base = Path(app_data) if app_data else (Path.home() / ".bpd")
        self.cache_dir = base / self.CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._manifest_hash: str | None = None
        self._manifest_files: list[str] | None = None
        self._stats = {
            "hits": {},
            "misses": {},
            "invalidations": {},
            "timings_ms": {},
            "manifest": {},
        }

    def get_stats(self) -> dict[str, Any]:
        return {
            "hits": dict(self._stats["hits"]),
            "misses": dict(self._stats["misses"]),
            "invalidations": dict(self._stats["invalidations"]),
            "timings_ms": dict(self._stats["timings_ms"]),
            "manifest": dict(self._stats["manifest"]),
        }

    def _mark(self, bucket: str, stage: str, delta: int = 1) -> None:
        target = self._stats.setdefault(bucket, {})
        target[stage] = int(target.get(stage, 0) or 0) + int(delta)

    def _record_timing(self, stage: str, ms: float) -> None:
        target = self._stats.setdefault("timings_ms", {})
        target[stage] = round(float(target.get(stage, 0.0) or 0.0) + float(ms), 3)

    def _cache_file(self, stage: str, key_hash: str) -> Path:
        return self.cache_dir / f"{stage}-{key_hash}.pkl"

    def _stage_version(self, stage: str) -> int:
        return int(_STAGE_VERSIONS.get(stage, 1))

    def _walk_files(self, root: Path) -> list[Path]:
        """Walk files excluding known large directories to avoid rglob(*) overhead."""
        files: list[Path] = []
        try:
            stack = [root]
            while stack:
                dir_path = stack.pop()
                try:
                    for entry in dir_path.iterdir():
                        rel = entry.relative_to(root).as_posix()
                        if self._is_excluded(rel):
                            continue
                        if entry.is_dir():
                            stack.append(entry)
                        elif entry.is_file():
                            files.append(entry)
                except (PermissionError, OSError):
                    continue
        except Exception:
            pass
        return files

    def compute_manifest_hash(self) -> str:
        if self._manifest_hash:
            return self._manifest_hash
        started = time.perf_counter()
        root = Path(self.project_path).resolve()
        digest = hashlib.sha1()
        if not root.exists():
            self._manifest_hash = "missing-project"
            return self._manifest_hash
        try:
            files = self._walk_files(root)
            self._manifest_files = [
                file_path.relative_to(root).as_posix()
                for file_path in files
                if file_path.is_file()
            ]
            for file_path in sorted(files, key=lambda p: p.relative_to(root).as_posix()):
                try:
                    rel = file_path.relative_to(root).as_posix()
                    stat = file_path.stat()
                    digest.update(rel.encode("utf-8", errors="ignore"))
                    digest.update(str(int(stat.st_mtime_ns)).encode("utf-8"))
                    digest.update(str(int(stat.st_size)).encode("utf-8"))
                except Exception:
                    continue
            self._manifest_hash = digest.hexdigest()[:24]
            self._stats["manifest"] = {
                "files_hashed": len(files),
                "compute_ms": round((time.perf_counter() - started) * 1000.0, 3),
            }
        except Exception:
            self._manifest_hash = "manifest-error"
        return self._manifest_hash

    def get_project_inventory(self) -> list[str]:
        """Expose the manifest walk so project detection does not walk again."""
        if self._manifest_files is None:
            self.compute_manifest_hash()
        return sorted(set(self._manifest_files or []))

    def _is_excluded(self, rel: str) -> bool:
        rel_norm = str(rel or "").replace("\\", "/").strip("/")
        if not rel_norm:
            return True
        parts = [part.lower() for part in rel_norm.split("/")]
        simple_names = {item.lower() for item in _DEFAULT_EXCLUDES if "/" not in item}
        if any(part in simple_names for part in parts):
            return True
        low = rel_norm.lower()
        return any(
            low == prefix.lower() or low.startswith(prefix.lower().rstrip("/") + "/")
            for prefix in _DEFAULT_EXCLUDES
            if "/" in prefix
        )

    def build_key_hash(self, stage: str, payload: dict[str, Any] | None = None) -> str:
        stable = {
            "stage": stage,
            "stage_version": self._stage_version(stage),
            "project_path": str(Path(self.project_path).resolve()),
            "manifest_hash": self.compute_manifest_hash(),
            "payload": payload or {},
        }
        raw = json.dumps(stable, sort_keys=True, default=str)
        return hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:24]

    def load(self, stage: str, payload: dict[str, Any] | None = None) -> Any | None:
        key_hash = self.build_key_hash(stage, payload)
        file_path = self._cache_file(stage, key_hash)
        start = time.perf_counter()
        try:
            if not file_path.exists():
                self._mark("misses", stage)
                return None
            with file_path.open("rb") as fh:
                value = pickle.load(fh)
            self._mark("hits", stage)
            return value
        except Exception:
            self._mark("invalidations", stage)
            with contextlib.suppress(Exception):
                file_path.unlink(missing_ok=True)
            return None
        finally:
            self._record_timing(stage, (time.perf_counter() - start) * 1000.0)

    def save(self, stage: str, value: Any, payload: dict[str, Any] | None = None) -> None:
        key_hash = self.build_key_hash(stage, payload)
        file_path = self._cache_file(stage, key_hash)
        tmp = file_path.with_suffix(f".{os.getpid()}-{threading.get_ident()}.tmp")
        start = time.perf_counter()
        try:
            with tmp.open("wb") as fh:
                pickle.dump(value, fh, protocol=pickle.HIGHEST_PROTOCOL)
            tmp.replace(file_path)
        except Exception:
            self._mark("invalidations", stage)
            with contextlib.suppress(Exception):
                tmp.unlink(missing_ok=True)
        finally:
            self._record_timing(stage, (time.perf_counter() - start) * 1000.0)
        self._prune_stage_entries(stage)

    def _prune_stage_entries(self, stage: str, keep: int = 64) -> None:
        """Bound cache growth while retaining recent project signatures."""
        try:
            entries = sorted(
                self.cache_dir.glob(f"{stage}-*.pkl"),
                key=lambda path: path.stat().st_mtime_ns,
                reverse=True,
            )
            for stale in entries[max(1, keep):]:
                stale.unlink(missing_ok=True)
        except OSError:
            return
