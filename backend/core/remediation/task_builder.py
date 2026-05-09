"""Build Remediation Run tasks from scan findings."""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.fp_feedback import FeedbackStore
from core.hashing import fast_hash_hex
from core.rule_engine import REGISTERED_RULES
from core.verification_helper import infer_verification_commands
from schemas.finding import Finding
from schemas.report import ScanReport

from .models import (
    FixRanking,
    FixStrategy,
    RemediationFindingRef,
    RemediationTask,
    TaskState,
)


CONFIDENCE_SCORE = {"high": 1.0, "medium": 0.6, "low": 0.3}
SAFETY_SCORE = {
    FixStrategy.SAFE_EDIT: 1.0,
    FixStrategy.GUIDED_EDIT: 0.7,
    FixStrategy.DEFER: 0.6,
    FixStrategy.SUPPRESS_WITH_EVIDENCE: 0.5,
    FixStrategy.MANUAL_REVIEW: 0.3,
}
RISK_LEVEL = {
    FixStrategy.SAFE_EDIT: "low",
    FixStrategy.GUIDED_EDIT: "medium",
    FixStrategy.DEFER: "low",
    FixStrategy.SUPPRESS_WITH_EVIDENCE: "medium",
    FixStrategy.MANUAL_REVIEW: "high",
}
EFFORT = {
    FixStrategy.SAFE_EDIT: "minutes",
    FixStrategy.GUIDED_EDIT: "hours",
    FixStrategy.DEFER: "minutes",
    FixStrategy.SUPPRESS_WITH_EVIDENCE: "minutes",
    FixStrategy.MANUAL_REVIEW: "days",
}


@dataclass(frozen=True)
class EnrichedFinding:
    ref: RemediationFindingRef
    finding: Finding
    rule: Any | None
    feedback_type: str


def build_tasks(
    report: ScanReport,
    selected_fingerprints: list[str],
    *,
    feedback_store: FeedbackStore | None = None,
) -> list[RemediationTask]:
    project_hash = fast_hash_hex(str(Path(report.project_path).resolve()), length=16)
    feedback_by_key = _load_feedback(feedback_store or FeedbackStore(), project_hash)
    selected = list(dict.fromkeys(str(fp) for fp in selected_fingerprints if str(fp).strip()))
    enriched = _enrich_findings(report, selected, feedback_by_key)
    groups = _group_findings(enriched)
    commands = infer_verification_commands(Path(report.project_path))
    now = datetime.now(timezone.utc)
    tasks: list[RemediationTask] = []
    for group_key, group_strategy, items in groups:
        for idx, chunk in enumerate(_chunks(items, 10), start=1):
            key = group_key if len(items) <= 10 else f"{group_key}::{idx}"
            affected_files = sorted({item.ref.file_path for item in chunk})
            rankings = rank_fix_strategies(chunk, affected_files)
            chosen = rankings[0].strategy
            task = RemediationTask(
                task_id=f"task_{uuid.uuid4().hex[:12]}",
                group_key=key,
                group_strategy=group_strategy,
                state=TaskState.PENDING,
                findings=[item.ref for item in chunk],
                affected_files=affected_files,
                fix_rankings=rankings,
                chosen_strategy=chosen,
                risk_notes=_risk_notes(chunk, rankings[0]),
                verification_commands=commands,
                agent_brief=_agent_brief(key, rankings[0], chunk, affected_files, commands),
                created_at=now,
                updated_at=now,
            )
            tasks.append(task)
    tasks.sort(key=lambda t: (-max((f.severity_weight for f in t.findings), default=0), t.group_key))
    return tasks


def rank_fix_strategies(items: list[EnrichedFinding], affected_files: list[str]) -> list[FixRanking]:
    strategies: list[tuple[FixStrategy, str]] = []
    if _is_safe_edit(items, affected_files):
        strategies.append((FixStrategy.SAFE_EDIT, "All findings are high-confidence, auto-fixable, and scoped to one file."))
    if _should_defer(items):
        strategies.append((FixStrategy.DEFER, "Project feedback or low-confidence severity makes documentation safer than editing."))
    if any(item.ref.false_positive_notes for item in items):
        strategies.append((FixStrategy.SUPPRESS_WITH_EVIDENCE, "Rule has known false-positive guidance; require evidence before suppression."))
    strategies.append((FixStrategy.GUIDED_EDIT, "Apply the rule guidance manually with verification after the edit."))
    if _requires_manual_review(items, affected_files):
        strategies.append((FixStrategy.MANUAL_REVIEW, "Scope or severity requires senior review before code changes."))
    strategies.append((FixStrategy.DEFER, "Last-resort option: document why no code change is being made."))

    deduped: list[tuple[FixStrategy, str]] = []
    seen: set[FixStrategy] = set()
    for strategy, rationale in strategies:
        if strategy in seen:
            continue
        seen.add(strategy)
        deduped.append((strategy, rationale))

    if len(deduped) == 1:
        deduped.append((FixStrategy.DEFER, "Fallback: document intentional deferral with evidence."))

    rankings = [_ranking(strategy, rationale, items, affected_files) for strategy, rationale in deduped]
    return _sort_rankings_conservatively(rankings)


def _enrich_findings(
    report: ScanReport,
    selected_fingerprints: list[str],
    feedback_by_key: dict[tuple[str, str], str],
) -> list[EnrichedFinding]:
    by_fp = {str(f.fingerprint): f for f in report.findings}
    out: list[EnrichedFinding] = []
    for fp in selected_fingerprints:
        finding = by_fp.get(fp)
        if finding is None:
            continue
        rule = REGISTERED_RULES.get(str(finding.rule_id))
        feedback_type = feedback_by_key.get((str(finding.fingerprint), str(finding.rule_id)), "")
        if feedback_type == "false_positive":
            continue
        severity = str(getattr(getattr(finding, "severity", ""), "value", getattr(finding, "severity", "")) or "")
        ref = RemediationFindingRef(
            fingerprint=str(finding.fingerprint),
            rule_id=str(finding.rule_id),
            file_path=str(finding.file),
            line=int(finding.line_start) if finding.line_start else None,
            severity=severity,
            severity_weight=int(getattr(rule, "severity_weight", 5) or 5) if rule else 5,
            confidence=str(getattr(rule, "confidence", "medium") or "medium") if rule else "medium",
            fix_suggestion=str(getattr(rule, "fix_suggestion", "") or finding.description or ""),
            false_positive_notes=str(getattr(rule, "false_positive_notes", "") or "") if rule else "",
            related_rules=list(getattr(rule, "related_rules", []) or []) if rule else [],
        )
        out.append(EnrichedFinding(ref=ref, finding=finding, rule=rule, feedback_type=feedback_type))
    return out


def _load_feedback(store: FeedbackStore, project_hash: str) -> dict[tuple[str, str], str]:
    rows: list[dict[str, object]] = []
    try:
        with store._locked_file(timeout_seconds=2.0) as handle:
            rows = store._read_entries(handle)
    except Exception:
        return {}
    out: dict[tuple[str, str], str] = {}
    for row in rows:
        if str(row.get("project_hash", "") or "") != project_hash:
            continue
        out[(str(row.get("fingerprint", "") or ""), str(row.get("rule_id", "") or ""))] = str(row.get("feedback_type", "") or "")
    return out


def _group_findings(items: list[EnrichedFinding]) -> list[tuple[str, str, list[EnrichedFinding]]]:
    remaining = list(items)
    groups: list[tuple[str, str, list[EnrichedFinding]]] = []

    related_sets: list[list[EnrichedFinding]] = []
    used: set[str] = set()
    for item in remaining:
        if item.ref.fingerprint in used:
            continue
        cluster = [other for other in remaining if _related(item, other)]
        if len(cluster) > 1:
            for member in cluster:
                used.add(member.ref.fingerprint)
            related_sets.append(cluster)
    for cluster in related_sets:
        primary = max(cluster, key=lambda x: x.ref.severity_weight)
        groups.append((primary.ref.rule_id, "by_related", cluster))
    remaining = [item for item in remaining if item.ref.fingerprint not in used]

    by_file_group: dict[tuple[str, str], list[EnrichedFinding]] = defaultdict(list)
    for item in remaining:
        group_name = str(getattr(item.rule, "group", "") or item.ref.rule_id)
        by_file_group[(item.ref.file_path, group_name)].append(item)
    used.clear()
    for (file_path, group_name), bucket in by_file_group.items():
        if len(bucket) > 1:
            groups.append((f"{file_path}::{group_name}", "by_file", bucket))
            used.update(item.ref.fingerprint for item in bucket)
    remaining = [item for item in remaining if item.ref.fingerprint not in used]

    by_rule: dict[str, list[EnrichedFinding]] = defaultdict(list)
    for item in remaining:
        by_rule[item.ref.rule_id].append(item)
    for rule_id, bucket in by_rule.items():
        if len(bucket) > 1:
            groups.append((rule_id, "by_rule", bucket))
            used.update(item.ref.fingerprint for item in bucket)
    remaining = [item for item in remaining if item.ref.fingerprint not in used]

    for item in remaining:
        groups.append((item.ref.fingerprint, "singleton", [item]))
    return groups


def _related(a: EnrichedFinding, b: EnrichedFinding) -> bool:
    if a.ref.fingerprint == b.ref.fingerprint:
        return True
    return a.ref.rule_id in set(b.ref.related_rules) or b.ref.rule_id in set(a.ref.related_rules)


def _chunks(items: list[EnrichedFinding], size: int) -> list[list[EnrichedFinding]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def _is_safe_edit(items: list[EnrichedFinding], affected_files: list[str]) -> bool:
    return (
        len(affected_files) == 1
        and all(bool(getattr(item.rule, "auto_fixable", False)) for item in items)
        and all(item.ref.confidence == "high" for item in items)
    )


def _should_defer(items: list[EnrichedFinding]) -> bool:
    for item in items:
        if item.feedback_type == "not_actionable":
            return True
        if item.ref.confidence == "low" and item.ref.severity in {"low", "medium"}:
            return True
    return False


def _requires_manual_review(items: list[EnrichedFinding], affected_files: list[str]) -> bool:
    if len(affected_files) > 5:
        return True
    return any(item.ref.severity_weight >= 10 and item.ref.confidence != "high" for item in items)


def _ranking(
    strategy: FixStrategy,
    rationale: str,
    items: list[EnrichedFinding],
    affected_files: list[str],
) -> FixRanking:
    confidence = min(CONFIDENCE_SCORE.get(item.ref.confidence, 0.6) for item in items) if items else 0.6
    safety = SAFETY_SCORE[strategy]
    scope = _scope_score(len(affected_files))
    score = round(confidence * 0.35 + safety * 0.40 + scope * 0.25, 4)
    return FixRanking(
        strategy=strategy,
        rank_score=score,
        rationale=rationale,
        risk_level=RISK_LEVEL[strategy],
        estimated_effort=EFFORT[strategy],
        acceptance_checks=_acceptance_checks(strategy, items),
    )


def _scope_score(file_count: int) -> float:
    if file_count <= 1:
        return 1.0
    if file_count <= 3:
        return 0.7
    if file_count <= 10:
        return 0.4
    return 0.1


def _sort_rankings_conservatively(rankings: list[FixRanking]) -> list[FixRanking]:
    ordered = sorted(rankings, key=lambda r: r.rank_score, reverse=True)
    changed = True
    while changed:
        changed = False
        for idx in range(len(ordered) - 1):
            left = ordered[idx]
            right = ordered[idx + 1]
            if abs(left.rank_score - right.rank_score) < 0.05 and SAFETY_SCORE[right.strategy] > SAFETY_SCORE[left.strategy]:
                ordered[idx], ordered[idx + 1] = right, left
                changed = True
    return ordered


def _acceptance_checks(strategy: FixStrategy, items: list[EnrichedFinding]) -> list[str]:
    sample = items[0].ref if items else None
    rule_id = sample.rule_id if sample else "selected rule"
    file_path = sample.file_path if sample else "selected file"
    fix = (sample.fix_suggestion if sample else "")[:100]
    if strategy == FixStrategy.SAFE_EDIT:
        return [
            "Run verification commands and confirm exit code 0",
            f"Run BPD rescan and confirm {rule_id} does not fire on {file_path}",
        ]
    if strategy == FixStrategy.GUIDED_EDIT:
        return [
            f"Confirm fix_suggestion was applied: {fix}",
            "Run verification commands",
            "Run BPD rescan and confirm finding count decreases",
        ]
    if strategy == FixStrategy.DEFER:
        return [
            "Document evidence that this is intentional",
            "Add suppression comment with ticket/PR reference",
        ]
    if strategy == FixStrategy.MANUAL_REVIEW:
        return [
            "Assign to senior developer for review",
            "Create tracking issue before touching code",
            "Do not apply without pair review",
        ]
    return [
        "Document concrete evidence before suppressing",
        "Run BPD rescan and confirm suppressed finding is intentionally excluded",
    ]


def _risk_notes(items: list[EnrichedFinding], top: FixRanking) -> list[str]:
    notes = [f"Chosen strategy {top.strategy.value} has {top.risk_level} risk."]
    for item in items:
        if item.ref.false_positive_notes:
            notes.append(f"{item.ref.rule_id}: {item.ref.false_positive_notes}")
    return notes


def _agent_brief(
    group_key: str,
    ranking: FixRanking,
    items: list[EnrichedFinding],
    affected_files: list[str],
    commands: list[str],
) -> str:
    rules = ", ".join(sorted({item.ref.rule_id for item in items}))
    files = ", ".join(affected_files)
    checks = "\n".join(f"- [ ] {check}" for check in ranking.acceptance_checks)
    cmd_block = "\n".join(commands)
    return (
        f"## Remediation task: {group_key}\n\n"
        f"Rules: {rules}\n"
        f"Files: {files}\n"
        f"Strategy: {ranking.strategy.value} ({ranking.risk_level})\n\n"
        f"{ranking.rationale}\n\n"
        f"Acceptance checks:\n{checks}\n\n"
        f"Verification commands:\n```bash\n{cmd_block}\n```"
    )
