"""Storage and path helpers for Remediation Runs."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

from config import ensure_app_data_dir
from core.hashing import fast_hash_hex


RUN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{6,80}$")


def project_hash_for_path(project_path: str | Path) -> str:
    return fast_hash_hex(str(Path(project_path).resolve()), length=16)


def validate_run_id(run_id: str) -> str:
    value = str(run_id or "").strip()
    if not RUN_ID_RE.match(value) or ".." in value or "/" in value or "\\" in value:
        raise ValueError("Invalid remediation run id")
    return value


def ensure_inside(base: Path, candidate: Path) -> Path:
    base_resolved = base.resolve()
    resolved = candidate.resolve()
    try:
        resolved.relative_to(base_resolved)
    except ValueError as exc:
        raise ValueError("Path escapes project root") from exc
    return resolved


def canonical_root() -> Path:
    root = ensure_app_data_dir() / "remediation_runs"
    root.mkdir(parents=True, exist_ok=True)
    return root


def canonical_run_dir(project_hash: str, run_id: str) -> Path:
    rid = validate_run_id(run_id)
    base = canonical_root() / str(project_hash)
    base.mkdir(parents=True, exist_ok=True)
    return ensure_inside(base, base / rid)


def ledger_path(project_hash: str, run_id: str) -> Path:
    return canonical_run_dir(project_hash, run_id) / "ledger.jsonl"


def run_snapshot_path(project_hash: str, run_id: str) -> Path:
    return canonical_run_dir(project_hash, run_id) / "run.json"


def find_run_dir(run_id: str) -> Path:
    rid = validate_run_id(run_id)
    root = canonical_root()
    for candidate in root.glob(f"*/{rid}"):
        if candidate.is_dir() and (candidate / "ledger.jsonl").exists():
            return ensure_inside(root, candidate)
    raise FileNotFoundError(rid)


def list_run_dirs_for_job(job_id: str) -> Iterable[Path]:
    root = canonical_root()
    for snapshot in root.glob("*/**/run.json"):
        try:
            data = json.loads(snapshot.read_text(encoding="utf-8"))
        except Exception:
            continue
        if str(data.get("source_job_id") or "") == str(job_id):
            yield snapshot.parent


def write_snapshot(project_hash: str, run_id: str, payload: dict) -> None:
    path = run_snapshot_path(project_hash, run_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)


def project_mirror_dir(project_path: str | Path, run_id: str) -> Path:
    root = Path(project_path).resolve()
    rid = validate_run_id(run_id)
    return ensure_inside(root, root / ".bpdoctor" / "remediation-runs" / rid)
