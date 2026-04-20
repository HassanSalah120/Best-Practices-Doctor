"""Persistent stage-output cache for scan pipeline."""

from __future__ import annotations

import hashlib
import json
import os
import pickle
import time
from pathlib import Path
from typing import Any


_STAGE_VERSIONS = {
    "detect_project": 1,
    "build_facts": 1,
    "run_rules": 1,
    "scoring": 1,
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
        self._stats = {
            "hits": {},
            "misses": {},
            "invalidations": {},
            "timings_ms": {},
        }

    def get_stats(self) -> dict[str, Any]:
        return {
            "hits": dict(self._stats["hits"]),
            "misses": dict(self._stats["misses"]),
            "invalidations": dict(self._stats["invalidations"]),
            "timings_ms": dict(self._stats["timings_ms"]),
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

    def compute_manifest_hash(self) -> str:
        if self._manifest_hash:
            return self._manifest_hash
        root = Path(self.project_path).resolve()
        digest = hashlib.sha1()
        if not root.exists():
            self._manifest_hash = "missing-project"
            return self._manifest_hash
        try:
            for file_path in sorted(root.rglob("*")):
                try:
                    if not file_path.is_file():
                        continue
                    rel = file_path.relative_to(root).as_posix()
                    if self._is_excluded(rel):
                        continue
                    stat = file_path.stat()
                    digest.update(rel.encode("utf-8", errors="ignore"))
                    digest.update(str(int(stat.st_mtime_ns)).encode("utf-8"))
                    digest.update(str(int(stat.st_size)).encode("utf-8"))
                except Exception:
                    continue
            self._manifest_hash = digest.hexdigest()[:24]
        except Exception:
            self._manifest_hash = "manifest-error"
        return self._manifest_hash

    def _is_excluded(self, rel: str) -> bool:
        rel_norm = str(rel or "").replace("\\", "/").strip("/")
        if not rel_norm:
            return True
        parts = rel_norm.split("/")
        for i in range(len(parts)):
            prefix = "/".join(parts[: i + 1])
            if prefix in _DEFAULT_EXCLUDES:
                return True
        return False

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
        if not file_path.exists():
            self._mark("misses", stage)
            return None
        try:
            with file_path.open("rb") as fh:
                value = pickle.load(fh)
            self._mark("hits", stage)
            return value
        except Exception:
            self._mark("invalidations", stage)
            try:
                file_path.unlink(missing_ok=True)
            except Exception:
                pass
            return None
        finally:
            self._record_timing(stage, (time.perf_counter() - start) * 1000.0)

    def save(self, stage: str, value: Any, payload: dict[str, Any] | None = None) -> None:
        key_hash = self.build_key_hash(stage, payload)
        file_path = self._cache_file(stage, key_hash)
        tmp = file_path.with_suffix(".tmp")
        start = time.perf_counter()
        try:
            with tmp.open("wb") as fh:
                pickle.dump(value, fh, protocol=pickle.HIGHEST_PROTOCOL)
            tmp.replace(file_path)
        except Exception:
            self._mark("invalidations", stage)
            try:
                tmp.unlink(missing_ok=True)
            except Exception:
                pass
        finally:
            self._record_timing(stage, (time.perf_counter() - start) * 1000.0)
