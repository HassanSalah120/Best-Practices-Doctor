"""CAS-chained append-only JSONL ledger for remediation runs."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from filelock import FileLock, Timeout

from .models import LedgerEntry, RemediationRun, TaskState, ledger_entry_hash


class LedgerCorruptionError(RuntimeError):
    """Raised when a remediation ledger hash chain is invalid."""


class RemediationLedger:
    """Append-only JSONL ledger with SHA-256 content-address chaining."""

    def __init__(self, ledger_path: Path):
        self.path = Path(ledger_path)
        self.lock_path = self.path.with_suffix(".lock")

    def append(self, op: str, payload: dict[str, Any]) -> LedgerEntry:
        try:
            with FileLock(str(self.lock_path), timeout=5, thread_local=False):
                self.path.parent.mkdir(parents=True, exist_ok=True)
                last = self.get_last_entry()
                seq = 1 if last is None else last.seq + 1
                prev_hash = "genesis" if last is None else last.self_hash
                timestamp = datetime.now(timezone.utc)
                self_hash = ledger_entry_hash(
                    seq=seq,
                    timestamp=timestamp,
                    op=op,
                    payload=payload,
                    prev_hash=prev_hash,
                )
                entry = LedgerEntry(
                    seq=seq,
                    timestamp=timestamp,
                    op=op,
                    payload=payload,
                    prev_hash=prev_hash,
                    self_hash=self_hash,
                )
                line = json.dumps(entry.model_dump(mode="json"), sort_keys=True) + "\n"
                self._atomic_append(line)
                return entry
        except Timeout as exc:
            raise TimeoutError(f"Timed out waiting for remediation ledger lock: {self.path}") from exc

    def load_all(self) -> list[LedgerEntry]:
        if not self.path.exists():
            return []
        entries: list[LedgerEntry] = []
        prev_hash = "genesis"
        prev_seq = 0
        with self.path.open("r", encoding="utf-8") as handle:
            for idx, raw in enumerate(handle, start=1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    entry = LedgerEntry.model_validate_json(line)
                except Exception as exc:
                    raise LedgerCorruptionError(f"Invalid ledger entry at line {idx}: {exc}") from exc
                expected_hash = ledger_entry_hash(
                    seq=entry.seq,
                    timestamp=entry.timestamp,
                    op=entry.op,
                    payload=entry.payload,
                    prev_hash=entry.prev_hash,
                )
                if entry.seq != prev_seq + 1:
                    raise LedgerCorruptionError(f"Ledger seq jump at line {idx}")
                if entry.prev_hash != prev_hash:
                    raise LedgerCorruptionError(f"Ledger prev_hash mismatch at line {idx}")
                if entry.self_hash != expected_hash:
                    raise LedgerCorruptionError(f"Ledger self_hash mismatch at line {idx}")
                entries.append(entry)
                prev_hash = entry.self_hash
                prev_seq = entry.seq
        return entries

    def get_last_entry(self) -> LedgerEntry | None:
        if not self.path.exists():
            return None
        last_line = ""
        with self.path.open("r", encoding="utf-8") as handle:
            for raw in handle:
                if raw.strip():
                    last_line = raw.strip()
        if not last_line:
            return None
        try:
            return LedgerEntry.model_validate_json(last_line)
        except Exception as exc:
            raise LedgerCorruptionError(f"Last ledger entry is invalid: {exc}") from exc

    def replay_run(self) -> RemediationRun | None:
        run: RemediationRun | None = None
        for entry in self.load_all():
            if entry.op == "run_created":
                run_payload = entry.payload.get("run")
                if not isinstance(run_payload, dict):
                    raise LedgerCorruptionError("run_created missing payload.run")
                run = RemediationRun.model_validate(run_payload)
                continue
            if run is None:
                raise LedgerCorruptionError(f"{entry.op} appeared before run_created")
            run = _apply_entry(run, entry)
        return run

    def _atomic_append(self, line: str) -> None:
        parent = self.path.parent
        parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=".ledger.", suffix=".tmp", dir=str(parent))
        try:
            with os.fdopen(fd, "wb") as tmp:
                if self.path.exists():
                    tmp.write(self.path.read_bytes())
                tmp.write(line.encode("utf-8"))
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(tmp_name, self.path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise


def _apply_entry(run: RemediationRun, entry: LedgerEntry) -> RemediationRun:
    data = run.model_copy(deep=True)
    now = entry.timestamp
    if entry.op == "task_updated":
        task_id = str(entry.payload.get("task_id") or "")
        state = entry.payload.get("state")
        for task in data.tasks:
            if task.task_id == task_id and state:
                task.state = TaskState(str(state))
                task.updated_at = now
        data.updated_at = now
        return data
    if entry.op == "evidence_recorded":
        task_id = str(entry.payload.get("task_id") or "")
        for task in data.tasks:
            if task.task_id == task_id and task.state == TaskState.PENDING:
                task.state = TaskState.IN_PROGRESS
                task.updated_at = now
        data.status = "active"
        data.updated_at = now
        return data
    if entry.op == "verification_recorded":
        results = entry.payload.get("results") or []
        if isinstance(results, list):
            from .models import VerificationResult

            data.verification_results = [VerificationResult.model_validate(item) for item in results]
            if data.verification_results and all(r.exit_code == 0 and not r.timed_out and not r.command_not_found for r in data.verification_results):
                for task in data.tasks:
                    if task.state in {TaskState.PENDING, TaskState.IN_PROGRESS}:
                        task.state = TaskState.VERIFIED
                        task.updated_at = now
                data.status = "verifying"
        data.updated_at = now
        return data
    if entry.op == "rescan_recorded":
        from .models import RescanComparison

        comparison = entry.payload.get("comparison")
        if isinstance(comparison, dict):
            data.rescan_comparison = RescanComparison.model_validate(comparison)
            selected = set(data.selected_fingerprints)
            resolved = set(data.rescan_comparison.resolved_fingerprints)
            if selected and selected.issubset(resolved):
                for task in data.tasks:
                    task.state = TaskState.COMPLETE
                    task.updated_at = now
                data.status = "complete"
        data.updated_at = now
        return data
    return data
