"""
Project Intelligence / memory layer.

Stores local per-project behavioral intelligence to improve triage and explainability
without suppressing findings automatically.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class RuleDispositionStats:
    total_updates: int = 0
    open: int = 0
    in_progress: int = 0
    fixed: int = 0
    skipped: int = 0
    last_status: str = "open"
    last_updated: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_updates": int(self.total_updates),
            "open": int(self.open),
            "in_progress": int(self.in_progress),
            "fixed": int(self.fixed),
            "skipped": int(self.skipped),
            "last_status": self.last_status,
            "last_updated": self.last_updated,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RuleDispositionStats:
        return cls(
            total_updates=int(data.get("total_updates", 0) or 0),
            open=int(data.get("open", 0) or 0),
            in_progress=int(data.get("in_progress", 0) or 0),
            fixed=int(data.get("fixed", 0) or 0),
            skipped=int(data.get("skipped", 0) or 0),
            last_status=str(data.get("last_status", "open") or "open"),
            last_updated=str(data.get("last_updated", "") or ""),
        )


@dataclass
class ProjectIntelligence:
    project_hash: str
    project_path: str
    created_at: str
    updated_at: str
    architecture_preferences: dict[str, int] = field(default_factory=dict)
    rule_dispositions: dict[str, RuleDispositionStats] = field(default_factory=dict)
    suppression_counts_by_rule: dict[str, int] = field(default_factory=dict)
    baseline_trends: dict[str, int] = field(default_factory=dict)
    recent_context_overrides: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_hash": self.project_hash,
            "project_path": self.project_path,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "architecture_preferences": dict(self.architecture_preferences),
            "rule_dispositions": {k: v.to_dict() for k, v in self.rule_dispositions.items()},
            "suppression_counts_by_rule": dict(self.suppression_counts_by_rule),
            "baseline_trends": dict(self.baseline_trends),
            "recent_context_overrides": list(self.recent_context_overrides),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProjectIntelligence:
        raw_rules = data.get("rule_dispositions", {})
        dispositions: dict[str, RuleDispositionStats] = {}
        if isinstance(raw_rules, dict):
            for rid, payload in raw_rules.items():
                if isinstance(payload, dict):
                    dispositions[str(rid)] = RuleDispositionStats.from_dict(payload)

        return cls(
            project_hash=str(data.get("project_hash", "") or ""),
            project_path=str(data.get("project_path", "") or ""),
            created_at=str(data.get("created_at", "") or ""),
            updated_at=str(data.get("updated_at", "") or ""),
            architecture_preferences={
                str(k): int(v or 0) for k, v in (data.get("architecture_preferences", {}) or {}).items()
            },
            rule_dispositions=dispositions,
            suppression_counts_by_rule={
                str(k): int(v or 0) for k, v in (data.get("suppression_counts_by_rule", {}) or {}).items()
            },
            baseline_trends={
                str(k): int(v or 0) for k, v in (data.get("baseline_trends", {}) or {}).items()
            },
            recent_context_overrides=list(data.get("recent_context_overrides", []) or []),
        )


class ProjectIntelligenceManager:
    """Persistence + advisory scoring helpers for project memory."""

    MEMORY_DIR = "project_intelligence"

    def __init__(self, app_data_dir: str | Path | None = None):
        if app_data_dir:
            root = Path(app_data_dir)
        else:
            app_data = os.environ.get("BPD_APP_DATA_DIR")
            root = Path(app_data) if app_data else (Path.home() / ".bpd")
        self.memory_dir = root / self.MEMORY_DIR
        self.memory_dir.mkdir(parents=True, exist_ok=True)

    def _project_hash(self, project_path: str) -> str:
        return hashlib.sha256(str(project_path).encode("utf-8", errors="ignore")).hexdigest()[:16]

    def _memory_file(self, project_hash: str) -> Path:
        return self.memory_dir / f"{project_hash}.json"

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def get_project(self, project_path: str) -> ProjectIntelligence:
        p = str(project_path or "")
        ph = self._project_hash(p)
        file_path = self._memory_file(ph)
        if file_path.exists():
            try:
                payload = json.loads(file_path.read_text(encoding="utf-8"))
                if isinstance(payload, dict):
                    return ProjectIntelligence.from_dict(payload)
            except Exception:
                pass
        now = self._now()
        return ProjectIntelligence(
            project_hash=ph,
            project_path=p,
            created_at=now,
            updated_at=now,
            baseline_trends={"new_total": 0, "resolved_total": 0, "unchanged_total": 0},
        )

    def save_project(self, memory: ProjectIntelligence) -> None:
        memory.updated_at = self._now()
        file_path = self._memory_file(memory.project_hash)
        tmp = file_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(memory.to_dict(), indent=2), encoding="utf-8")
        tmp.replace(file_path)

    def record_finding_status(
        self,
        project_path: str,
        *,
        rule_id: str,
        status: str,
    ) -> ProjectIntelligence:
        memory = self.get_project(project_path)
        rid = str(rule_id or "").strip().lower()
        st = str(status or "open").strip().lower()
        stats = memory.rule_dispositions.get(rid) or RuleDispositionStats()
        stats.total_updates += 1
        if st == "open":
            stats.open += 1
        elif st == "in_progress":
            stats.in_progress += 1
        elif st == "fixed":
            stats.fixed += 1
        elif st == "skipped":
            stats.skipped += 1
        else:
            stats.open += 1
            st = "open"
        stats.last_status = st
        stats.last_updated = self._now()
        memory.rule_dispositions[rid] = stats
        self.save_project(memory)
        return memory

    def record_context_overrides(
        self,
        project_path: str,
        overrides: dict[str, Any] | None,
    ) -> ProjectIntelligence:
        if not overrides:
            return self.get_project(project_path)
        memory = self.get_project(project_path)
        payload = {
            "captured_at": self._now(),
            "overrides": dict(overrides),
        }
        entries = list(memory.recent_context_overrides)
        entries.append(payload)
        memory.recent_context_overrides = entries[-20:]

        arch = str((overrides or {}).get("architecture_profile", "") or "").strip().lower()
        if arch:
            memory.architecture_preferences[arch] = memory.architecture_preferences.get(arch, 0) + 1

        self.save_project(memory)
        return memory

    def record_baseline_diff(
        self,
        project_path: str,
        *,
        new_count: int,
        resolved_count: int,
        unchanged_count: int,
    ) -> ProjectIntelligence:
        memory = self.get_project(project_path)
        trends = dict(memory.baseline_trends or {})
        trends["new_total"] = int(trends.get("new_total", 0) or 0) + int(new_count or 0)
        trends["resolved_total"] = int(trends.get("resolved_total", 0) or 0) + int(resolved_count or 0)
        trends["unchanged_total"] = int(trends.get("unchanged_total", 0) or 0) + int(unchanged_count or 0)
        memory.baseline_trends = trends
        self.save_project(memory)
        return memory

    def record_suppression(self, project_path: str, *, rule_id: str) -> ProjectIntelligence:
        memory = self.get_project(project_path)
        rid = str(rule_id or "*").strip().lower()
        memory.suppression_counts_by_rule[rid] = memory.suppression_counts_by_rule.get(rid, 0) + 1
        self.save_project(memory)
        return memory

    def get_rule_memory_factor(self, project_path: str, rule_id: str) -> float:
        """
        Advisory multiplier for prioritization.
        >1 means team usually fixes this quickly.
        <1 means team usually defers/ignores this rule.
        """
        memory = self.get_project(project_path)
        stats = memory.rule_dispositions.get(str(rule_id or "").strip().lower())
        if not stats or stats.total_updates <= 0:
            return 1.0
        fixed_ratio = stats.fixed / max(1, stats.total_updates)
        skipped_ratio = stats.skipped / max(1, stats.total_updates)
        if skipped_ratio >= 0.6:
            return 0.88
        if fixed_ratio >= 0.65:
            return 1.08
        return 1.0
