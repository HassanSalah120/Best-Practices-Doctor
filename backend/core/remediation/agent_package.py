"""Generate agent work packages for remediation runs."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from .models import RemediationRun, RemediationTask
from .storage import project_mirror_dir

CONSTRAINTS = [
    "Do not change public API routes or response shapes",
    "Preserve all existing tests",
]

OPERATING_PROTOCOL = [
    "Define the verifiable goal first \u2192 smallest change \u2192 tightest test",
    "Read PROJECT_MAP.md for architecture-sensitive changes",
    "Document disconnected work instead of leaving orphans",
    "Check package versions only when adding deps",
]


def build_agent_package(run: RemediationRun) -> dict[str, Any]:
    markdown = build_markdown(run)
    payload = build_json_payload(run)
    return {
        "markdown": markdown,
        "json_payload": payload,
        "files": {
            "REMEDIATION.md": markdown,
            "agent-package.json": json.dumps(payload, indent=2, ensure_ascii=True, default=str),
        },
    }


def build_markdown(run: RemediationRun) -> str:
    all_findings = [finding for task in run.tasks for finding in task.findings]
    lines = [
        f"# Remediation: {run.run_id[:8]}",
        f"Project: {run.project_path} | Scan: {run.source_job_id}",
        f"Generated: {run.created_at.isoformat()} | {len(run.tasks)} task(s), {len(all_findings)} finding(s)",
        "",
        "## Read First",
        "- Read AGENTS.md and .bpdoctor/agent/RULES.md",
        "- Plan + Verify only. No risky refactors without review.",
        "- Record evidence + verify after each task.",
        "",
        "## Operating Protocol",
    ]
    lines.extend(f"- {item}" for item in OPERATING_PROTOCOL)
    lines.extend(
        [
            "",
            "## Tasks",
        ],
    )
    for idx, task in enumerate(_ordered_tasks(run.tasks), start=1):
        top = task.fix_rankings[0]
        severities: dict[str, int] = {}
        for finding in task.findings:
            severities[finding.severity] = severities.get(finding.severity, 0) + 1
        lines.extend(
            [
                "",
                f"### Task {idx}: {task.group_key}",
                f"Strategy: {task.chosen_strategy.value} | Risk: {top.risk_level}",
                f"Files: {', '.join(task.affected_files)}",
                f"Findings: {len(task.findings)} ({', '.join(f'{k}={v}' for k, v in sorted(severities.items()))})",
                "",
                f"What: {top.rationale}",
                task.findings[0].fix_suggestion if task.findings else "",
                "",
                "Acceptance:",
            ],
        )
        lines.extend(f"- [ ] {check}" for check in top.acceptance_checks)
        notes = [f.false_positive_notes for f in task.findings if f.false_positive_notes]
        if notes:
            lines.extend(["", f"FP note: {notes[0]}", "Document evidence. Do not suppress blindly."])
    commands = sorted({cmd for task in run.tasks for cmd in task.verification_commands})
    lines.extend(["", "## Verify", "Run after ALL tasks:", "```bash"])
    lines.extend(commands)
    lines.extend(["```", "", "## Constraints"])
    lines.extend(f"- {item}" for item in CONSTRAINTS)
    return "\n".join(lines).strip() + "\n"


def build_json_payload(run: RemediationRun) -> dict[str, Any]:
    return {
        "run_id": run.run_id,
        "project_hash": run.project_hash,
        "source_scan_id": run.source_job_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "constraints": CONSTRAINTS,
        "operating_protocol": OPERATING_PROTOCOL,
        "tasks": [
            {
                "task_id": task.task_id,
                "group_key": task.group_key,
                "chosen_strategy": task.chosen_strategy.value,
                "risk_level": task.fix_rankings[0].risk_level if task.fix_rankings else "medium",
                "findings": [finding.model_dump(mode="json") for finding in task.findings],
                "affected_files": task.affected_files,
                "fix_suggestion": task.findings[0].fix_suggestion if task.findings else "",
                "acceptance_checks": task.fix_rankings[0].acceptance_checks if task.fix_rankings else [],
                "verification_commands": task.verification_commands,
            }
            for task in _ordered_tasks(run.tasks)
        ],
        "expected_evidence": {
            "per_task": ["verification_result", "agent_notes"],
            "post_run": ["verification_commands_output", "rescan_comparison"],
        },
    }


def write_project_mirror(run: RemediationRun) -> list[str]:
    warnings: list[str] = []
    try:
        package = build_agent_package(run)
        target = project_mirror_dir(run.project_path, run.run_id)
        target.mkdir(parents=True, exist_ok=True)
        (target / "REMEDIATION.md").write_text(package["files"]["REMEDIATION.md"], encoding="utf-8")
        (target / "agent-package.json").write_text(package["files"]["agent-package.json"], encoding="utf-8")
    except Exception as exc:
        warnings.append(f"Project mirror write failed: {exc}")
    return warnings


def _ordered_tasks(tasks: list[RemediationTask]) -> list[RemediationTask]:
    return sorted(tasks, key=lambda task: (-max((f.severity_weight for f in task.findings), default=0), task.group_key))
