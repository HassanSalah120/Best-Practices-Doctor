"""Strict pydantic contracts for Remediation Runs."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FixStrategy(StrEnum):
    SAFE_EDIT = "safe_edit"
    GUIDED_EDIT = "guided_edit"
    MANUAL_REVIEW = "manual_review"
    DEFER = "defer"
    SUPPRESS_WITH_EVIDENCE = "suppress_with_evidence"


class TaskState(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    VERIFIED = "verified"
    COMPLETE = "complete"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


class RemediationFindingRef(StrictModel):
    fingerprint: str
    rule_id: str
    file_path: str
    line: int | None
    severity: str
    severity_weight: int
    confidence: str
    fix_suggestion: str
    false_positive_notes: str
    related_rules: list[str] = Field(default_factory=list)


class FixRanking(StrictModel):
    strategy: FixStrategy
    rank_score: float
    rationale: str
    risk_level: str
    estimated_effort: str
    acceptance_checks: list[str] = Field(default_factory=list)


class RemediationTask(StrictModel):
    task_id: str
    group_key: str
    group_strategy: str
    state: TaskState
    findings: list[RemediationFindingRef]
    affected_files: list[str]
    fix_rankings: list[FixRanking]
    chosen_strategy: FixStrategy
    risk_notes: list[str] = Field(default_factory=list)
    verification_commands: list[str] = Field(default_factory=list)
    agent_brief: str
    created_at: datetime
    updated_at: datetime


class VerificationResult(StrictModel):
    command: str
    cwd: str
    started_at: datetime
    completed_at: datetime | None
    exit_code: int | None
    stdout_truncated: str
    stderr_truncated: str
    timed_out: bool
    command_not_found: bool


class RescanComparison(StrictModel):
    baseline_scan_id: str
    rescan_scan_id: str
    resolved_fingerprints: list[str]
    unchanged_fingerprints: list[str]
    new_fingerprints: list[str]
    score_delta: dict[str, float]
    severity_deltas: dict[str, int]


class RemediationRun(StrictModel):
    run_id: str
    source_job_id: str
    project_path: str
    project_hash: str
    status: str
    selected_fingerprints: list[str]
    tasks: list[RemediationTask]
    verification_results: list[VerificationResult] = Field(default_factory=list)
    rescan_comparison: RescanComparison | None = None
    warnings: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class LedgerEntry(StrictModel):
    seq: int
    timestamp: datetime
    op: str
    payload: dict[str, Any]
    prev_hash: str
    self_hash: str


def ledger_entry_hash(
    *,
    seq: int,
    timestamp: datetime | str,
    op: str,
    payload: dict[str, Any],
    prev_hash: str,
) -> str:
    timestamp_value = timestamp.isoformat() if isinstance(timestamp, datetime) else str(timestamp)
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    raw = f"{seq}|{timestamp_value}|{op}|{payload_json}|{prev_hash}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
