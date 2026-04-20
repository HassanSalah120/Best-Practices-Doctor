"""
API Routes
REST endpoints with SSE progress streaming.
"""
from pathlib import Path
import os
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, Query, Depends
from fastapi.responses import StreamingResponse
from fastapi.responses import Response

from core.job_manager import job_manager, CancellationToken, JobManager
from core.pipeline import ScanPipelineRequest, run_scan_pipeline
from core.detector import ProjectDetector
from core.ruleset import Ruleset
from core.sarif import findings_to_sarif
from core.hashing import fast_hash_hex
from schemas.report import ScanJob, ScanReport
from .auth import verify_token

router = APIRouter(prefix="/api", dependencies=[Depends(verify_token)])


# --- Request/Response Models ---

class ScanRequest(BaseModel):
    """Request to start a scan."""
    path: str
    ruleset_path: str | None = None
    baseline_profile: str | None = None
    differential_mode: bool = False
    changed_files: list[str] | None = None
    pr_mode: bool = False
    pr_gate_preset: str | None = None
    selected_rules: list[str] | None = None  # For advanced profile: only run these rules
    project_context_overrides: dict[str, object] | None = None


class ContextSuggestRequest(BaseModel):
    """Request payload for pre-scan project context suggestion."""
    path: str
    ruleset_path: str | None = None


class ScanResponse(BaseModel):
    """Response after starting a scan."""
    job_id: str
    status: str


class ErrorResponse(BaseModel):
    """Error response."""
    error: str
    details: str | None = None

class ActiveRulesetProfileRequest(BaseModel):
    name: str = Field(..., description="Active ruleset profile name (e.g., startup, balanced, strict)")

class BaselineCompareResponse(BaseModel):
    profile: str
    baseline_path: str
    has_baseline: bool
    new_findings_count: int
    resolved_findings_count: int
    unchanged_findings_count: int
    new_finding_fingerprints: list[str] = Field(default_factory=list)
    resolved_finding_fingerprints: list[str] = Field(default_factory=list)
    unchanged_finding_fingerprints: list[str] = Field(default_factory=list)
    new_counts_by_severity: dict[str, int] = Field(default_factory=dict)
    resolved_counts_by_severity: dict[str, int] = Field(default_factory=dict)
    unchanged_counts_by_severity: dict[str, int] = Field(default_factory=dict)


# --- Health Check ---

@router.get("/health")
async def health_check():
    """Health check endpoint for Tauri/Frontend."""
    return {"status": "ok", "version": "1.0.0"}


def _suggest_overrides_from_context_payload(payload: dict[str, object]) -> dict[str, object]:
    project_type = str(payload.get("project_type") or payload.get("project_business_context") or "unknown").strip()
    architecture_style = str(payload.get("architecture_style") or payload.get("backend_architecture_profile") or "unknown").strip()
    capabilities_payload = payload.get("capabilities") or payload.get("backend_capabilities") or {}
    expectations_payload = payload.get("team_expectations") or payload.get("backend_team_expectations") or {}

    overrides: dict[str, object] = {}
    if project_type and project_type != "unknown":
        overrides["project_type"] = project_type
    if architecture_style and architecture_style != "unknown":
        overrides["architecture_profile"] = architecture_style

    capabilities: dict[str, bool] = {}
    if isinstance(capabilities_payload, dict):
        for key, info in capabilities_payload.items():
            if not isinstance(info, dict):
                continue
            enabled = bool(info.get("enabled", False))
            confidence = float(info.get("confidence", 0.0) or 0.0)
            if enabled and confidence >= 0.55:
                capabilities[str(key)] = True
    if capabilities:
        overrides["capabilities"] = capabilities

    expectations: dict[str, bool] = {}
    if isinstance(expectations_payload, dict):
        for key, info in expectations_payload.items():
            if not isinstance(info, dict):
                continue
            enabled = bool(info.get("enabled", False))
            confidence = float(info.get("confidence", 0.0) or 0.0)
            if enabled and confidence >= 0.6:
                expectations[str(key)] = True
    if expectations:
        overrides["team_expectations"] = expectations

    return overrides


def _pin_overrides_from_context_payload(payload: dict[str, object]) -> dict[str, object]:
    """
    Build an explicit context snapshot from detected payload.

    Unlike suggestion mode, this keeps both enabled and disabled capability/team
    states so subsequent rescans stay stable even when heuristic detection shifts.
    """
    project_type = str(payload.get("project_type") or payload.get("project_business_context") or "unknown").strip()
    architecture_style = str(payload.get("architecture_style") or payload.get("backend_architecture_profile") or "unknown").strip()
    capabilities_payload = payload.get("capabilities") or payload.get("backend_capabilities") or {}
    expectations_payload = payload.get("team_expectations") or payload.get("backend_team_expectations") or {}

    overrides: dict[str, object] = {"context_lock_mode": "pinned_detected_snapshot"}
    if project_type and project_type != "unknown":
        overrides["project_type"] = project_type
    if architecture_style and architecture_style != "unknown":
        overrides["architecture_profile"] = architecture_style

    capabilities: dict[str, bool] = {}
    if isinstance(capabilities_payload, dict):
        for key, info in capabilities_payload.items():
            if not isinstance(info, dict):
                continue
            capabilities[str(key)] = bool(info.get("enabled", False))
    if capabilities:
        overrides["capabilities"] = capabilities

    expectations: dict[str, bool] = {}
    if isinstance(expectations_payload, dict):
        for key, info in expectations_payload.items():
            if not isinstance(info, dict):
                continue
            expectations[str(key)] = bool(info.get("enabled", False))
    if expectations:
        overrides["team_expectations"] = expectations

    return overrides


@router.post("/context/suggest")
async def suggest_project_context(request: ContextSuggestRequest):
    """
    Build a lightweight pre-scan context suggestion from project structure.

    This powers the setup UI so users can accept/edit detected context before a full scan.
    """
    import asyncio
    from analysis.facts_builder import FactsBuilder

    path = Path(request.path)
    if not path.exists():
        raise HTTPException(status_code=400, detail=f"Path does not exist: {request.path}")
    if not path.is_dir():
        raise HTTPException(status_code=400, detail=f"Path is not a directory: {request.path}")

    detector = ProjectDetector(str(path))
    project_info = await asyncio.to_thread(detector.detect)

    ruleset = Ruleset.load_default(override_path=request.ruleset_path)
    builder = FactsBuilder(
        project_info=project_info,
        ignore_patterns=ruleset.scan.ignore,
        max_file_size_kb=ruleset.scan.max_file_size_kb,
        max_files=ruleset.scan.max_files,
        context_overrides=None,
    )
    facts = await asyncio.to_thread(builder.build)

    project_context = getattr(facts, "project_context", None)
    context_payload = project_context.model_dump() if project_context is not None else {}
    suggested_overrides = _suggest_overrides_from_context_payload(context_payload)
    pinned_overrides = _pin_overrides_from_context_payload(context_payload)

    return {
        "framework": str(context_payload.get("backend_framework", "unknown") or "unknown"),
        "project_context": context_payload,
        "suggested_context": suggested_overrides,
        "pinned_context": pinned_overrides,
    }


# --- Scan function using real analysis pipeline ---

async def run_scan(
    project_path: str,
    ruleset_path: str | None,
    baseline_profile: str | None,
    differential_mode: bool,
    changed_files: list[str] | None,
    pr_mode: bool,
    pr_gate_preset: str | None,
    selected_rules: list[str] | None,
    project_context_overrides: dict[str, object] | None,
    job_id: str,
    token: CancellationToken,
    manager: JobManager,
) -> ScanReport:
    """Thin adapter that forwards scan execution to the composable pipeline."""
    pipeline_request = ScanPipelineRequest(
        project_path=project_path,
        ruleset_path=ruleset_path,
        baseline_profile=baseline_profile,
        differential_mode=differential_mode,
        changed_files=changed_files,
        pr_mode=pr_mode,
        pr_gate_preset=pr_gate_preset,
        selected_rules=selected_rules,
        project_context_overrides=project_context_overrides,
    )
    return await run_scan_pipeline(
        pipeline_request,
        job_id=job_id,
        token=token,
        manager=manager,
    )


# --- Endpoints ---

@router.post("/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest):
    """Start a new code quality scan."""
    # Validate path exists
    path = Path(request.path)
    if not path.exists():
        raise HTTPException(status_code=400, detail=f"Path does not exist: {request.path}")
    
    if not path.is_dir():
        raise HTTPException(status_code=400, detail=f"Path is not a directory: {request.path}")
    
    # Create job
    job_id, token = job_manager.create_job(request.path)
    
    # Start scan in background
    await job_manager.start_job(
        job_id,
        run_scan,
        request.path,
        request.ruleset_path,
        request.baseline_profile,
        request.differential_mode,
        request.changed_files,
        request.pr_mode,
        request.pr_gate_preset,
        request.selected_rules,
        request.project_context_overrides,
    )
    
    return ScanResponse(job_id=job_id, status="running")


@router.get("/scan/{job_id}")
async def get_scan_status(job_id: str):
    """Get scan status or results."""
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
    
    result = {"job": job.model_dump()}
    
    # Include report if completed
    if job.status.value == "completed":
        report = job_manager.get_report(job_id)
        if report:
            result["report"] = report.model_dump()
    
    return result


@router.get("/scan/{job_id}/sarif")
async def get_scan_sarif(job_id: str):
    """Get completed scan findings as SARIF 2.1.0 JSON."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")

    return findings_to_sarif(report.findings)


@router.get("/scan/{job_id}/pr-gate")
async def evaluate_scan_pr_gate(
    job_id: str,
    preset: str | None = Query(default=None, description="PR gate preset (startup|balanced|strict)"),
    profile: str | None = Query(default=None, description="Baseline profile override"),
    include_sarif: bool = Query(default=False, description="Include SARIF payload for blocking findings"),
):
    """Evaluate PR gate policy against NEW findings (baseline diff)."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")

    try:
        from core.baseline import baseline_diff_from_report, compare_baseline_snapshot
        from core.pr_gate import evaluate_pr_gate

        diff = baseline_diff_from_report(report, profile=profile or getattr(report, "baseline_profile", None))
        if not diff.has_baseline and not diff.new_fingerprints:
            # Fallback for older reports without baseline metadata.
            diff = compare_baseline_snapshot(
                report.project_path,
                report.findings,
                profile=profile or getattr(report, "baseline_profile", None),
            )
        gate = evaluate_pr_gate(
            report,
            preset_name=preset,
            profile=profile or getattr(report, "baseline_profile", None),
            baseline_diff=diff,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to evaluate PR gate: {e}")

    payload = {
        "preset": gate.preset,
        "profile": gate.profile,
        "passed": gate.passed,
        "reason": gate.reason,
        "baseline_has_previous": gate.baseline_has_previous,
        "baseline_path": gate.baseline_path,
        "total_new_findings": gate.total_new_findings,
        "eligible_new_findings": gate.eligible_new_findings,
        "blocking_findings_count": gate.blocking_findings_count,
        "blocking_fingerprints": gate.blocking_fingerprints,
        "blocking_findings": [f.model_dump() for f in gate.blocking_findings],
        "by_severity": gate.by_severity,
        "by_rule": gate.by_rule,
    }

    if include_sarif:
        payload["sarif"] = findings_to_sarif(gate.blocking_findings)

    return payload


@router.get("/scan/{job_id}/events")
async def scan_events(job_id: str):
    """SSE endpoint for real-time scan progress."""
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
    
    return StreamingResponse(
        job_manager.subscribe(job_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


@router.post("/scan/{job_id}/cancel")
async def cancel_scan(job_id: str):
    """Cancel a running scan."""
    success = await job_manager.cancel_job(job_id)
    
    if not success:
        raise HTTPException(status_code=400, detail="Could not cancel job (may not be running)")
    
    return {"status": "cancelled", "job_id": job_id}


@router.post("/scan/{job_id}/baseline/reset", response_model=ScanReport)
async def reset_baseline(job_id: str):
    """Reset the baseline to the current report (clears "new issues" for this project)."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")

    try:
        from core.baseline import reset_baseline_to_report

        reset_baseline_to_report(report, profile=getattr(report, "baseline_profile", None))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reset baseline: {e}")

    return report


@router.get("/scan/{job_id}/baseline", response_model=BaselineCompareResponse)
async def compare_baseline(job_id: str, profile: str | None = Query(default=None)):
    """Compare current report with persisted baseline snapshot without mutating baseline."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")

    try:
        from core.baseline import compare_baseline_snapshot

        prof = profile or getattr(report, "baseline_profile", None)
        diff = compare_baseline_snapshot(report.project_path, report.findings, profile=prof)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to compare baseline: {e}")

    return BaselineCompareResponse(
        profile=diff.baseline_profile,
        baseline_path=diff.baseline_path,
        has_baseline=diff.has_baseline,
        new_findings_count=len(diff.new_fingerprints),
        resolved_findings_count=len(diff.resolved_fingerprints),
        unchanged_findings_count=len(diff.unchanged_fingerprints),
        new_finding_fingerprints=list(diff.new_fingerprints),
        resolved_finding_fingerprints=list(diff.resolved_fingerprints),
        unchanged_finding_fingerprints=list(diff.unchanged_fingerprints),
        new_counts_by_severity=dict(diff.new_counts_by_severity),
        resolved_counts_by_severity=dict(diff.resolved_counts_by_severity),
        unchanged_counts_by_severity=dict(diff.unchanged_counts_by_severity),
    )


@router.post("/scan/{job_id}/baseline/save", response_model=ScanReport)
async def save_baseline(job_id: str, profile: str | None = Query(default=None)):
    """Save baseline snapshot from current report findings and clear new-issue delta."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")

    try:
        from core.baseline import reset_baseline_to_report

        reset_baseline_to_report(report, profile=profile or getattr(report, "baseline_profile", None))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save baseline: {e}")

    return report


@router.get("/scan/{job_id}/files")
async def get_scan_files(job_id: str):
    """Get list of files with issues."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    
    return {
        "files": report.file_summaries,
        "total": len(report.file_summaries),
    }


@router.get("/scan/{job_id}/file")
async def get_file_issues(job_id: str, path: str = Query(..., description="File path")):
    """Get issues for a specific file."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    
    # Find findings for this file
    file_findings = [f for f in report.findings if f.file == path]
    
    return {
        "path": path,
        "findings": [f.model_dump() for f in file_findings],
        "count": len(file_findings),
    }


@router.get("/scan/{job_id}/file/content")
async def get_file_content(job_id: str, path: str = Query(..., description="File path")):
    """Get file content for code view."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    
    try:
        file_path = Path(report.project_path) / path
        if not file_path.exists():
            raise HTTPException(status_code=404, detail=f"File not found: {path}")
        
        # Security check - ensure file is within project
        try:
            file_path.resolve().relative_to(Path(report.project_path).resolve())
        except ValueError:
            raise HTTPException(status_code=403, detail="Access denied")
        
        content = file_path.read_text(encoding="utf-8", errors="replace")
        
        return {
            "path": path,
            "content": content,
            "size": len(content),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read file: {e}")


class FindingStatusUpdateRequest(BaseModel):
    """Update finding work status for project intelligence tracking."""
    status: str = Field(..., description="open|in_progress|fixed|skipped")
    note: str = ""


class FindingFeedbackRequest(BaseModel):
    """One-click feedback payload for false-positive collection."""
    feedback_type: str = Field(..., description="false_positive|not_actionable|correct")


def _latest_completed_report() -> ScanReport | None:
    reports = list(getattr(job_manager, "_reports", {}).values())
    if not reports:
        return None
    return reports[-1]


@router.get("/scan/{job_id}/findings/{fingerprint}/explain")
async def explain_finding(job_id: str, fingerprint: str):
    """Return explainability/trust payload for a finding."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")

    finding = next((f for f in report.findings if str(getattr(f, "fingerprint", "")) == str(fingerprint)), None)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding not found: {fingerprint}")

    trust_payload = {}
    if isinstance(getattr(finding, "metadata", None), dict):
        trust_candidate = finding.metadata.get("trust")
        if isinstance(trust_candidate, dict):
            trust_payload = trust_candidate

    return {
        "fingerprint": finding.fingerprint,
        "rule_id": finding.rule_id,
        "file": finding.file,
        "line_start": finding.line_start,
        "title": finding.title,
        "severity": str(getattr(finding.severity, "value", finding.severity)),
        "classification": str(getattr(finding.classification, "value", finding.classification)),
        "why_flagged": finding.why_flagged or "",
        "why_not_ignored": finding.why_not_ignored or "",
        "evidence_signals": list(getattr(finding, "evidence_signals", []) or []),
        "trust": trust_payload,
    }


@router.get("/scan/{job_id}/findings/{fingerprint}/suggest-fix")
async def suggest_fix_for_finding(job_id: str, fingerprint: str):
    """Return intelligent fix suggestion for one finding."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")

    finding = next((f for f in report.findings if str(getattr(f, "fingerprint", "")) == str(fingerprint)), None)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding not found: {fingerprint}")

    file_path = Path(report.project_path) / finding.file
    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {finding.file}")

    try:
        from core.auto_fix import AutoFixEngine

        content = file_path.read_text(encoding="utf-8", errors="replace")
        project_context = {}
        if isinstance(getattr(report, "analysis_debug", None), dict):
            project_context = dict(report.analysis_debug.get("project_context") or {})
        engine = AutoFixEngine(project_context=project_context)
        fix = engine.get_fix_suggestion(finding, content)
        return {
            "fingerprint": finding.fingerprint,
            "rule_id": finding.rule_id,
            "has_fix": fix is not None,
            "fix": FixSuggestionResponse(**fix.to_dict()).model_dump() if fix else None,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to suggest fix: {e}")


@router.get("/scan/{job_id}/triage")
async def get_scan_triage(job_id: str):
    """Return triage-plan projection from report."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    return {
        "triage_plan": [item.model_dump() for item in (getattr(report, "triage_plan", []) or [])],
        "top_5_first": list(getattr(report, "top_5_first", []) or []),
        "safe_to_defer": list(getattr(report, "safe_to_defer", []) or []),
    }


@router.post("/scan/{job_id}/findings/{fingerprint}/status")
async def update_finding_status(job_id: str, fingerprint: str, request: FindingStatusUpdateRequest):
    """Track finding status for project intelligence (advisory memory)."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    finding = next((f for f in report.findings if str(getattr(f, "fingerprint", "")) == str(fingerprint)), None)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding not found: {fingerprint}")

    status = str(request.status or "").strip().lower()
    if status not in {"open", "in_progress", "fixed", "skipped"}:
        raise HTTPException(status_code=400, detail="Invalid status; use open|in_progress|fixed|skipped")

    try:
        from core.project_memory import ProjectIntelligenceManager

        manager = ProjectIntelligenceManager()
        memory = manager.record_finding_status(
            report.project_path,
            rule_id=finding.rule_id,
            status=status,
        )
        return {
            "status": "updated",
            "fingerprint": finding.fingerprint,
            "rule_id": finding.rule_id,
            "finding_status": status,
            "note": request.note or "",
            "memory_updated_at": memory.updated_at,
            "project_hash": memory.project_hash,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update finding status: {e}")


@router.post("/findings/{fingerprint}/feedback")
async def submit_finding_feedback(fingerprint: str, request: FindingFeedbackRequest):
    """Record false-positive/not-actionable/correct feedback for the latest scan finding."""
    feedback_type = str(request.feedback_type or "").strip().lower()
    if feedback_type not in {"false_positive", "not_actionable", "correct"}:
        raise HTTPException(status_code=400, detail="Invalid feedback_type")

    report = _latest_completed_report()
    if report is None:
        raise HTTPException(status_code=404, detail="No completed scan available")

    finding = next((f for f in report.findings if str(getattr(f, "fingerprint", "")) == str(fingerprint)), None)
    if finding is None:
        raise HTTPException(status_code=404, detail=f"Finding not found in latest scan: {fingerprint}")

    try:
        from core.fp_feedback import FeedbackBusyError, FeedbackStore

        store = FeedbackStore()
        store.record(
            fingerprint=fingerprint,
            rule_id=finding.rule_id,
            project_hash=fast_hash_hex(report.project_path, length=16),
            feedback_type=feedback_type,
        )
        return {"status": "recorded"}
    except FeedbackBusyError:
        return Response(
            content='{"status":"busy","retry_after":2}',
            status_code=409,
            media_type="application/json",
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to record feedback: {e}")


@router.get("/feedback/summary")
async def get_feedback_summary():
    """Return aggregated feedback counters grouped by rule id."""
    try:
        from core.fp_feedback import FeedbackBusyError, FeedbackStore

        store = FeedbackStore()
        return {"by_rule": store.summary()}
    except FeedbackBusyError:
        return Response(
            content='{"status":"busy","retry_after":2}',
            status_code=409,
            media_type="application/json",
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to summarize feedback: {e}")


@router.get("/ruleset")
async def get_ruleset():
    """Get the current ruleset configuration."""
    try:
        return Ruleset.load_default().model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load ruleset: {e}")

@router.get("/rulesets")
async def list_rulesets():
    """List available ruleset profiles and the active one."""
    try:
        from core.ruleset_profiles import list_profiles
        from core.app_settings import get_active_ruleset_profile

        profiles = list_profiles()
        active = get_active_ruleset_profile(default="startup")
        if active not in profiles and profiles:
            # If settings points to a missing profile, report a safe default.
            active = profiles[0]
        return {"profiles": profiles, "active_profile": active}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list rulesets: {e}")


@router.get("/rulesets/{name}")
async def get_ruleset_profile_yaml(name: str):
    """Get raw YAML for a ruleset profile."""
    try:
        from core.ruleset_profiles import read_profile_yaml

        yml = read_profile_yaml(name)
        if yml is None:
            raise HTTPException(status_code=404, detail=f"Ruleset profile not found: {name}")
        return Response(content=yml, media_type="text/yaml; charset=utf-8")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read ruleset profile: {e}")


@router.put("/rulesets/active")
async def set_active_ruleset_profile(req: ActiveRulesetProfileRequest):
    """Set the active ruleset profile (persisted in app data settings.json)."""
    try:
        from core.ruleset_profiles import list_profiles
        from core.app_settings import set_active_ruleset_profile

        name = (req.name or "").strip().lower()
        profiles = list_profiles()
        if name not in profiles:
            raise HTTPException(status_code=400, detail=f"Unknown ruleset profile: {name}")
        set_active_ruleset_profile(name)
        return {"active_profile": name, "profiles": profiles}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to set active ruleset profile: {e}")


@router.put("/ruleset")
async def update_ruleset(ruleset_data: dict):
    """Update and save the default ruleset."""
    try:
        # Validate
        ruleset = Ruleset(**ruleset_data)

        # Save (user-scoped). In Tauri runtime the sidecar gets `BPD_APP_DATA_DIR`,
        # so persist edits there instead of the current working directory.
        app_data_dir = os.environ.get("BPD_APP_DATA_DIR")
        if app_data_dir:
            out_path = Path(app_data_dir) / "ruleset.yaml"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            ruleset.save(out_path)
        else:
            ruleset.save_default()

        return {"status": "updated", "ruleset": ruleset.model_dump()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid ruleset: {str(e)}")


@router.get("/rules/metadata")
async def get_rule_metadata():
    """Get rule metadata grouped by layer and category for advanced profile configuration."""
    try:
        from core.rule_metadata import get_rules_grouped_for_ui
        return get_rules_grouped_for_ui()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load rule metadata: {e}")


# --- Suppression Management ---

class SuppressionRequest(BaseModel):
    """Request to add a suppression."""
    rule_id: str
    file_pattern: str = ""
    line_start: int | None = None
    line_end: int | None = None
    reason: str = ""
    until: str | None = None  # ISO date string
    created_by: str = ""


class SuppressionResponse(BaseModel):
    """Response for suppression operations."""
    id: str
    rule_id: str
    file_pattern: str
    line_start: int | None
    line_end: int | None
    reason: str
    until: str | None
    created_at: str
    created_by: str


@router.get("/scan/{job_id}/suppressions")
async def list_suppressions(job_id: str):
    """List all suppressions for the project."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    
    try:
        from core.suppression import SuppressionManager
        
        manager = SuppressionManager(report.project_path)
        suppressions = manager.list_suppressions()
        
        return {
            "suppressions": [SuppressionResponse(
                id=s.id,
                rule_id=s.rule_id,
                file_pattern=s.file_pattern,
                line_start=s.line_start,
                line_end=s.line_end,
                reason=s.reason,
                until=s.until.isoformat() if s.until else None,
                created_at=s.created_at.isoformat() if s.created_at else "",
                created_by=s.created_by,
            ).model_dump() for s in suppressions],
            "total": len(suppressions),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list suppressions: {e}")


@router.post("/scan/{job_id}/suppressions", response_model=SuppressionResponse)
async def add_suppression(job_id: str, request: SuppressionRequest):
    """Add a new suppression rule."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    
    try:
        from core.suppression import SuppressionManager
        from datetime import date as date_type
        
        manager = SuppressionManager(report.project_path)
        
        until = None
        if request.until:
            try:
                until = date_type.fromisoformat(request.until)
            except ValueError:
                pass
        
        rule = manager.add_suppression(
            rule_id=request.rule_id,
            file_pattern=request.file_pattern,
            line_start=request.line_start,
            line_end=request.line_end,
            reason=request.reason,
            until=until,
            created_by=request.created_by,
        )
        try:
            from core.project_memory import ProjectIntelligenceManager

            ProjectIntelligenceManager().record_suppression(
                report.project_path,
                rule_id=request.rule_id or "*",
            )
        except Exception:
            pass
        
        return SuppressionResponse(
            id=rule.id,
            rule_id=rule.rule_id,
            file_pattern=rule.file_pattern,
            line_start=rule.line_start,
            line_end=rule.line_end,
            reason=rule.reason,
            until=rule.until.isoformat() if rule.until else None,
            created_at=rule.created_at.isoformat() if rule.created_at else "",
            created_by=rule.created_by,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add suppression: {e}")


@router.delete("/scan/{job_id}/suppressions/{suppression_id}")
async def remove_suppression(job_id: str, suppression_id: str):
    """Remove a suppression rule."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    
    try:
        from core.suppression import SuppressionManager
        
        manager = SuppressionManager(report.project_path)
        removed = manager.remove_suppression(suppression_id)
        
        if not removed:
            raise HTTPException(status_code=404, detail=f"Suppression not found: {suppression_id}")
        
        return {"status": "removed", "id": suppression_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to remove suppression: {e}")


@router.post("/scan/{job_id}/suppressions/clear-expired")
async def clear_expired_suppressions(job_id: str):
    """Clear all expired suppression rules."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    
    try:
        from core.suppression import SuppressionManager
        
        manager = SuppressionManager(report.project_path)
        removed_count = manager.clear_expired()
        
        return {"status": "cleared", "removed_count": removed_count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear expired suppressions: {e}")


# --- Auto-Fix Management ---

class FixSuggestionResponse(BaseModel):
    """Response for fix suggestion."""
    rule_id: str
    title: str
    description: str
    original_code: str
    fixed_code: str
    line_start: int
    line_end: int
    confidence: float
    auto_applicable: bool
    strategy: str = "risky"
    confidence_breakdown: dict[str, float] = Field(default_factory=dict)
    why_correct_for_project: str = ""
    risk_notes: str = ""
    requires_human_review: bool = True
    diff: str


@router.get("/scan/{job_id}/fixes")
async def get_fix_suggestions(job_id: str):
    """Get auto-fix suggestions for all findings."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    
    try:
        from core.auto_fix import AutoFixEngine
        
        project_context = {}
        if isinstance(getattr(report, "analysis_debug", None), dict):
            project_context = dict(report.analysis_debug.get("project_context") or {})
        engine = AutoFixEngine(project_context=project_context)
        fixes_by_file = engine.get_fixes_for_findings(report.findings, report.project_path)
        
        result = {}
        for file_path, fixes in fixes_by_file.items():
            result[file_path] = [FixSuggestionResponse(**f.to_dict()).model_dump() for f in fixes]
        
        return {
            "fixes": result,
            "total_files": len(result),
            "total_fixes": sum(len(f) for f in fixes_by_file.values()),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get fix suggestions: {e}")


@router.get("/scan/{job_id}/fixes/{file_path:path}")
async def get_file_fix_suggestions(job_id: str, file_path: str):
    """Get auto-fix suggestions for a specific file."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    
    try:
        from core.auto_fix import AutoFixEngine
        
        # Get findings for this file
        file_findings = [f for f in report.findings if f.file == file_path]
        if not file_findings:
            return {"fixes": [], "total": 0}
        
        project_context = {}
        if isinstance(getattr(report, "analysis_debug", None), dict):
            project_context = dict(report.analysis_debug.get("project_context") or {})
        engine = AutoFixEngine(project_context=project_context)
        file_content_path = Path(report.project_path) / file_path
        
        if not file_content_path.exists():
            raise HTTPException(status_code=404, detail=f"File not found: {file_path}")
        
        content = file_content_path.read_text(encoding="utf-8", errors="replace")
        
        fixes = []
        for finding in file_findings:
            fix = engine.get_fix_suggestion(finding, content)
            if fix:
                fixes.append(FixSuggestionResponse(**fix.to_dict()).model_dump())
        
        return {
            "file": file_path,
            "fixes": fixes,
            "total": len(fixes),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get fix suggestions: {e}")


@router.post("/scan/{job_id}/fixes/{file_path:path}/apply")
async def apply_fix(job_id: str, file_path: str, line_start: int = Query(...), dry_run: bool = Query(True)):
    """Apply a fix to a file (dry_run=True by default for safety)."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    
    try:
        from core.auto_fix import AutoFixEngine
        
        project_context = {}
        if isinstance(getattr(report, "analysis_debug", None), dict):
            project_context = dict(report.analysis_debug.get("project_context") or {})
        engine = AutoFixEngine(project_context=project_context)
        full_path = Path(report.project_path) / file_path
        
        if not full_path.exists():
            raise HTTPException(status_code=404, detail=f"File not found: {file_path}")
        
        content = full_path.read_text(encoding="utf-8", errors="replace")
        
        # Find the finding for this line
        finding = next(
            (f for f in report.findings if f.file == file_path and f.line_start == line_start),
            None
        )
        if not finding:
            raise HTTPException(status_code=404, detail=f"No finding at line {line_start}")
        
        fix = engine.get_fix_suggestion(finding, content)
        if not fix:
            raise HTTPException(status_code=400, detail="No fix available for this finding")
        
        if (not fix.auto_applicable or fix.strategy != "safe") and not dry_run:
            raise HTTPException(
                status_code=400,
                detail="Only safe auto-applicable fixes can be applied automatically; use dry_run preview for risky/refactor fixes",
            )
        
        success, result = engine.apply_fix(full_path, fix, dry_run=dry_run)
        
        if not success:
            raise HTTPException(status_code=500, detail=f"Failed to apply fix: {result}")
        
        return {
            "status": "applied" if not dry_run else "preview",
            "file": file_path,
            "line_start": line_start,
            "original_code": fix.original_code,
            "fixed_code": fix.fixed_code,
            "diff": fix.to_diff(),
            "new_content": result if dry_run else None,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to apply fix: {e}")


# --- Scan History & Trends ---

@router.get("/history/projects")
async def list_project_history():
    """List all projects with scan history."""
    try:
        from core.scan_history import ScanHistoryManager
        
        manager = ScanHistoryManager()
        projects = manager.list_projects()
        
        return {"projects": projects, "total": len(projects)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list projects: {e}")


@router.get("/scan/{job_id}/history")
async def get_scan_history(job_id: str, limit: int = Query(10, ge=1, le=50)):
    """Get scan history for the project associated with a job."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    
    try:
        from core.scan_history import ScanHistoryManager
        
        manager = ScanHistoryManager()
        history = manager.get_history_by_path(report.project_path)
        
        return {
            "project_path": report.project_path,
            "project_hash": history.project_hash,
            "scans": [s.to_dict() for s in history.scans[-limit:]],
            "total_scans": len(history.scans),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get history: {e}")


@router.get("/scan/{job_id}/trends")
async def get_scan_trends(job_id: str, limit: int = Query(10, ge=2, le=50)):
    """Get trend analysis for the project."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    
    try:
        from core.scan_history import ScanHistoryManager
        
        manager = ScanHistoryManager()
        project_hash = fast_hash_hex(report.project_path, 16)
        trend = manager.get_trend(project_hash, limit=limit)
        
        return trend
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get trends: {e}")


@router.get("/scan/{job_id}/trends/category/{category}")
async def get_category_trend(job_id: str, category: str, limit: int = Query(10, ge=2, le=50)):
    """Get trend for a specific category."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    
    try:
        from core.scan_history import ScanHistoryManager
        
        manager = ScanHistoryManager()
        project_hash = fast_hash_hex(report.project_path, 16)
        trend = manager.get_category_trend(project_hash, category, limit=limit)
        
        return trend
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get category trend: {e}")


@router.post("/scan/{job_id}/history/save")
async def save_scan_to_history(job_id: str):
    """Save current scan to history for trend tracking."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    
    try:
        from core.scan_history import ScanHistoryManager
        
        manager = ScanHistoryManager()
        summary = manager.add_scan(report, profile="startup")
        
        return {
            "status": "saved",
            "job_id": job_id,
            "overall_score": summary.overall_score,
            "grade": summary.grade,
            "total_findings": summary.total_findings,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save scan to history: {e}")


@router.delete("/scan/{job_id}/history")
async def clear_scan_history(job_id: str):
    """Clear scan history for the project."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    
    try:
        from core.scan_history import ScanHistoryManager
        
        manager = ScanHistoryManager()
        project_hash = fast_hash_hex(report.project_path, 16)
        cleared = manager.clear_history(project_hash)
        
        return {"status": "cleared" if cleared else "not_found"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear history: {e}")


# --- Incremental Scanning ---

@router.get("/scan/{job_id}/incremental/status")
async def get_incremental_status(job_id: str):
    """Get incremental scan status and manifest stats."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    
    try:
        from core.incremental import IncrementalScanManager
        
        manager = IncrementalScanManager(report.project_path)
        stats = manager.get_stats()
        
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get incremental status: {e}")


@router.get("/scan/{job_id}/incremental/changes")
async def detect_file_changes(job_id: str, files: str = Query("", description="Comma-separated file list")):
    """Detect file changes since last scan."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    
    try:
        from core.incremental import IncrementalScanManager
        
        manager = IncrementalScanManager(report.project_path)
        
        # Parse file list
        file_list = [f.strip() for f in files.split(",") if f.strip()] if files else []
        
        # If no files provided, get from facts
        if not file_list and hasattr(report, "facts") and report.facts:
            file_list = getattr(report.facts, "files", [])
        
        changes = manager.detect_changes(file_list)
        
        return {
            "project_path": report.project_path,
            "changes": changes,
            "total_changed": len(changes["added"]) + len(changes["modified"]) + len(changes["deleted"]),
            "total_unchanged": len(changes["unchanged"]),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to detect changes: {e}")


@router.post("/scan/{job_id}/incremental/update")
async def update_incremental_manifest(job_id: str, files: str = Query("", description="Comma-separated file list")):
    """Update manifest with scanned files."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    
    try:
        from core.incremental import IncrementalScanManager
        
        manager = IncrementalScanManager(report.project_path)
        
        # Parse file list
        file_list = [f.strip() for f in files.split(",") if f.strip()] if files else []
        
        # If no files provided, get from report
        if not file_list:
            file_list = [f.file for f in report.findings if f.file]
            if hasattr(report, "facts") and report.facts:
                file_list = list(set(file_list + list(getattr(report.facts, "files", []))))
        
        manager.update_manifest(file_list)
        stats = manager.get_stats()
        
        return {
            "status": "updated",
            "files_updated": len(file_list),
            "manifest": stats,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update manifest: {e}")


@router.delete("/scan/{job_id}/incremental/manifest")
async def clear_incremental_manifest(job_id: str):
    """Clear the incremental scan manifest (force full rescan)."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    
    try:
        from core.incremental import IncrementalScanManager
        
        manager = IncrementalScanManager(report.project_path)
        manager.clear_manifest()
        
        return {"status": "cleared"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear manifest: {e}")


# --- AST Cache ---

@router.get("/scan/{job_id}/ast-cache/stats")
async def get_ast_cache_stats(job_id: str):
    """Get AST cache statistics."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    
    try:
        from core.ast_cache import ASTCacheManager
        
        cache = ASTCacheManager(report.project_path)
        stats = cache.get_stats()
        
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get AST cache stats: {e}")


@router.delete("/scan/{job_id}/ast-cache")
async def clear_ast_cache(job_id: str):
    """Clear the AST cache."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    
    try:
        from core.ast_cache import ASTCacheManager
        
        cache = ASTCacheManager(report.project_path)
        count = cache.clear_cache()
        
        return {"status": "cleared", "files_removed": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear AST cache: {e}")


@router.post("/scan/{job_id}/ast-cache/invalidate")
async def invalidate_ast_cache_file(job_id: str, file_path: str = Query(..., description="File path to invalidate")):
    """Invalidate AST cache for a specific file."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    
    try:
        from core.ast_cache import ASTCacheManager
        
        cache = ASTCacheManager(report.project_path)
        invalidated = cache.invalidate(file_path)
        cache.save()
        
        return {"status": "invalidated" if invalidated else "not_found", "file": file_path}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to invalidate cache: {e}")
