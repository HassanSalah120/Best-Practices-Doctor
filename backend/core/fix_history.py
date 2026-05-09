"""Persistent history for applied Auto-Fix edits."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from config import ensure_app_data_dir
from core.hashing import fast_hash_hex


class FixHistoryConflictError(RuntimeError):
    """Raised when the file no longer matches the recorded undo/redo state."""


def _content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


@dataclass
class FixHistoryEntry:
    id: str
    job_id: str
    project_hash: str
    project_path: str
    file: str
    line_start: int
    rule_id: str
    title: str
    before_hash: str
    after_hash: str
    before_content: str
    after_content: str
    applied_at: str
    undone: bool = False
    undone_at: str | None = None
    redone_at: str | None = None

    def to_dict(self, *, include_content: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.id,
            "job_id": self.job_id,
            "project_hash": self.project_hash,
            "project_path": self.project_path,
            "file": self.file,
            "line_start": self.line_start,
            "rule_id": self.rule_id,
            "title": self.title,
            "before_hash": self.before_hash,
            "after_hash": self.after_hash,
            "applied_at": self.applied_at,
            "undone": self.undone,
            "undone_at": self.undone_at,
            "redone_at": self.redone_at,
        }
        if include_content:
            data["before_content"] = self.before_content
            data["after_content"] = self.after_content
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FixHistoryEntry":
        return cls(
            id=str(data.get("id") or ""),
            job_id=str(data.get("job_id") or ""),
            project_hash=str(data.get("project_hash") or ""),
            project_path=str(data.get("project_path") or ""),
            file=str(data.get("file") or ""),
            line_start=int(data.get("line_start") or 1),
            rule_id=str(data.get("rule_id") or ""),
            title=str(data.get("title") or ""),
            before_hash=str(data.get("before_hash") or ""),
            after_hash=str(data.get("after_hash") or ""),
            before_content=str(data.get("before_content") or ""),
            after_content=str(data.get("after_content") or ""),
            applied_at=str(data.get("applied_at") or ""),
            undone=bool(data.get("undone", False)),
            undone_at=data.get("undone_at") or None,
            redone_at=data.get("redone_at") or None,
        )


@dataclass
class FixHistoryFile:
    version: str = "1.0"
    entries: list[FixHistoryEntry] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "entries": [entry.to_dict(include_content=True) for entry in self.entries],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FixHistoryFile":
        entries = [
            FixHistoryEntry.from_dict(item)
            for item in data.get("entries", [])
            if isinstance(item, dict)
        ]
        return cls(version=str(data.get("version") or "1.0"), entries=entries)


class FixHistoryManager:
    """Store applied fix history per project for real undo/redo."""

    HISTORY_DIR = "fix_history"

    def __init__(self, project_path: str | Path):
        self.project_path = Path(project_path).resolve()
        self.project_hash = fast_hash_hex(str(self.project_path), length=16)
        self.history_path = ensure_app_data_dir() / self.HISTORY_DIR / f"{self.project_hash}.json"
        self.history_path.parent.mkdir(parents=True, exist_ok=True)
        self.history = self._load()

    def _load(self) -> FixHistoryFile:
        if not self.history_path.exists():
            return FixHistoryFile()
        try:
            raw = json.loads(self.history_path.read_text(encoding="utf-8") or "{}")
            if isinstance(raw, dict):
                return FixHistoryFile.from_dict(raw)
        except Exception:
            return FixHistoryFile()
        return FixHistoryFile()

    def _save(self) -> None:
        self.history_path.write_text(
            json.dumps(self.history.to_dict(), indent=2),
            encoding="utf-8",
        )

    def list_entries(self, job_id: str | None = None) -> list[FixHistoryEntry]:
        entries = self.history.entries
        if job_id:
            entries = [entry for entry in entries if entry.job_id == job_id]
        return sorted(entries, key=lambda entry: entry.applied_at, reverse=True)

    def get_entry(self, entry_id: str) -> FixHistoryEntry:
        return self._get_entry(entry_id)

    def record_apply(
        self,
        *,
        job_id: str,
        file: str,
        line_start: int,
        rule_id: str,
        title: str,
        before_content: str,
        after_content: str,
    ) -> FixHistoryEntry:
        entry = FixHistoryEntry(
            id=f"fix-{uuid.uuid4().hex[:12]}",
            job_id=job_id,
            project_hash=self.project_hash,
            project_path=str(self.project_path),
            file=file,
            line_start=line_start,
            rule_id=rule_id,
            title=title,
            before_hash=_content_hash(before_content),
            after_hash=_content_hash(after_content),
            before_content=before_content,
            after_content=after_content,
            applied_at=datetime.now().isoformat(),
        )
        self.history.entries.append(entry)
        self._save()
        return entry

    def undo(self, entry_id: str) -> FixHistoryEntry:
        entry = self._get_entry(entry_id)
        file_path = self._resolve_file(entry.file)
        current = file_path.read_text(encoding="utf-8", errors="replace")
        if _content_hash(current) != entry.after_hash:
            raise FixHistoryConflictError(
                "Cannot undo because the file changed after the fix was applied."
            )
        file_path.write_text(entry.before_content, encoding="utf-8")
        entry.undone = True
        entry.undone_at = datetime.now().isoformat()
        self._save()
        return entry

    def redo(self, entry_id: str) -> FixHistoryEntry:
        entry = self._get_entry(entry_id)
        file_path = self._resolve_file(entry.file)
        current = file_path.read_text(encoding="utf-8", errors="replace")
        if _content_hash(current) != entry.before_hash:
            raise FixHistoryConflictError(
                "Cannot redo because the file no longer matches the recorded pre-fix content."
            )
        file_path.write_text(entry.after_content, encoding="utf-8")
        entry.undone = False
        entry.redone_at = datetime.now().isoformat()
        self._save()
        return entry

    def _get_entry(self, entry_id: str) -> FixHistoryEntry:
        for entry in self.history.entries:
            if entry.id == entry_id:
                return entry
        raise KeyError(entry_id)

    def _resolve_file(self, rel_path: str) -> Path:
        full_path = (self.project_path / rel_path).resolve()
        try:
            full_path.relative_to(self.project_path)
        except ValueError as exc:
            raise ValueError(f"Path escapes project root: {rel_path}") from exc
        if not full_path.exists():
            raise FileNotFoundError(rel_path)
        return full_path
