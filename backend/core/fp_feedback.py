"""
False-positive feedback persistence.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO


class FeedbackBusyError(Exception):
    """Raised when feedback storage lock cannot be acquired."""


@dataclass
class FeedbackEntry:
    fingerprint: str
    rule_id: str
    project_hash: str
    feedback_type: str
    timestamp: str

    def to_dict(self) -> dict[str, str]:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "project_hash": self.project_hash,
            "feedback_type": self.feedback_type,
            "timestamp": self.timestamp,
        }


class FeedbackStore:
    """Append-style JSONL feedback store with deduplicated updates."""

    VALID_TYPES = {"false_positive", "not_actionable", "correct"}

    def __init__(self, path: Path | None = None):
        self.path = path or (Path.home() / ".bpdoctor" / "fp_feedback.json")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")

    def record(
        self,
        *,
        fingerprint: str,
        rule_id: str,
        project_hash: str,
        feedback_type: str,
    ) -> None:
        if feedback_type not in self.VALID_TYPES:
            raise ValueError(f"Invalid feedback_type: {feedback_type}")

        now = datetime.now(timezone.utc).isoformat()
        entry = FeedbackEntry(
            fingerprint=str(fingerprint or "").strip(),
            rule_id=str(rule_id or "").strip(),
            project_hash=str(project_hash or "").strip(),
            feedback_type=feedback_type,
            timestamp=now,
        )
        if not entry.fingerprint or not entry.rule_id:
            raise ValueError("fingerprint and rule_id are required")

        with self._locked_file(timeout_seconds=2.0) as handle:
            rows = self._read_entries(handle)
            key = (entry.fingerprint, entry.rule_id)
            updated = False
            for idx, row in enumerate(rows):
                row_key = (str(row.get("fingerprint", "")), str(row.get("rule_id", "")))
                if row_key == key:
                    rows[idx] = entry.to_dict()
                    updated = True
                    break
            if not updated:
                rows.append(entry.to_dict())
            self._write_entries(handle, rows)

    def summary(self) -> dict[str, dict[str, int]]:
        with self._locked_file(timeout_seconds=2.0) as handle:
            rows = self._read_entries(handle)
        by_rule: dict[str, dict[str, int]] = {}
        for row in rows:
            rule_id = str(row.get("rule_id", "") or "")
            feedback_type = str(row.get("feedback_type", "") or "")
            if not rule_id or feedback_type not in self.VALID_TYPES:
                continue
            bucket = by_rule.setdefault(
                rule_id,
                {"false_positive": 0, "not_actionable": 0, "correct": 0},
            )
            bucket[feedback_type] += 1
        return by_rule

    def _read_entries(self, handle: TextIO) -> list[dict[str, object]]:
        handle.seek(0)
        rows: list[dict[str, object]] = []
        for raw in handle.readlines():
            line = str(raw or "").strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except Exception:
                continue
            if isinstance(payload, dict):
                rows.append(payload)
        return rows

    def _write_entries(self, handle: TextIO, rows: list[dict[str, object]]) -> None:
        handle.seek(0)
        handle.truncate()
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())

    def _locked_file(self, timeout_seconds: float):
        start = time.monotonic()
        handle = self.path.open("r+", encoding="utf-8")
        try:
            while True:
                try:
                    self._acquire_lock(handle)
                    break
                except OSError:
                    if (time.monotonic() - start) >= timeout_seconds:
                        raise FeedbackBusyError("feedback store is busy")
                    time.sleep(0.05)
            return _LockedFileContext(self, handle)
        except Exception:
            handle.close()
            raise

    def _acquire_lock(self, handle: TextIO) -> None:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            return
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _release_lock(self, handle: TextIO) -> None:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            return
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class _LockedFileContext:
    """Internal context manager for locked file handles."""

    def __init__(self, store: FeedbackStore, handle: TextIO):
        self.store = store
        self.handle = handle

    def __enter__(self) -> TextIO:
        return self.handle

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            self.store._release_lock(self.handle)
        finally:
            self.handle.close()
