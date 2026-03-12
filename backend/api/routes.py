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
from core.detector import ProjectDetector
from core.ruleset import Ruleset, DEFAULT_RULESET
from core.sarif import findings_to_sarif
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


# --- Scan function using real analysis pipeline ---

async def run_scan(
    project_path: str,
    ruleset_path: str | None,
    baseline_profile: str | None,
    differential_mode: bool,
    changed_files: list[str] | None,
    pr_mode: bool,
    pr_gate_preset: str | None,
    job_id: str,
    token: CancellationToken,
    manager: JobManager,
) -> ScanReport:
    """
    Main scan function - orchestrates the full analysis pipeline.
    
    Pipeline stages:
    1. Detect project type
    2. Build raw facts from source files
    3. Run rules against facts
    4. Calculate scores from findings
    5. Generate report
    """
    import asyncio
    import uuid
    import time
    from datetime import datetime
    from schemas import ScanReport, QualityScores, FileSummary, ProjectInfo
    from analysis.facts_builder import FactsBuilder
    from core.rule_engine import create_engine
    from core.scoring import ScoringEngine
    
    start_time = time.perf_counter()
    
    # job_id is now passed explicitly
    loop = asyncio.get_running_loop()
    
    # --- Phase 1: Detect project type ---
    await manager.update_progress(job_id, 5.0, "detecting")
    token.check()
    
    detector = ProjectDetector(project_path)
    project_info = await asyncio.to_thread(detector.detect)
    
    # --- Phase 2: Build facts from source files ---
    await manager.update_progress(job_id, 10.0, "parsing")
    token.check()
    
    # Load ruleset (override path > active profile > user-saved > packaged default > built-in)
    ruleset = None
    if ruleset_path:
        # Use explicit override path if provided
        try:
            ruleset = Ruleset.load(ruleset_path)
        except Exception:
            pass
    
    if ruleset is None and baseline_profile:
        # Load the active profile ruleset (strict/balanced/startup)
        try:
            from core.ruleset_profiles import get_profile_path
            profile_path = get_profile_path(baseline_profile)
            if profile_path:
                ruleset = Ruleset.load(profile_path)
        except Exception:
            pass
    
    if ruleset is None:
        # Fall back to default loading chain
        ruleset = Ruleset.load_default(override_path=ruleset_path)

    ignore_patterns = ruleset.scan.ignore
    
    # Create facts builder with cancellation check
    facts_builder = FactsBuilder(
        project_info=project_info,
        ignore_patterns=ignore_patterns,
        cancellation_check=token.is_cancelled,
        max_file_size_kb=ruleset.scan.max_file_size_kb,
        max_files=ruleset.scan.max_files,
    )
    
    # Progress callback for facts building - handled thread-safely
    def on_facts_progress(progress):
        if progress.total_files > 0:
            pct = 10.0 + (progress.files_processed / progress.total_files) * 40.0
            asyncio.run_coroutine_threadsafe(
                manager.update_progress(
                    job_id,
                    pct,
                    "parsing",
                    current_file=progress.current_file,
                    files_processed=progress.files_processed,
                    files_total=progress.total_files,
                ),
                loop
            )
    
    # Build facts (run in thread to not block)
    facts = await asyncio.to_thread(facts_builder.build, on_facts_progress)
    token.check()
    
    # --- Phase 2.5: Calculate derived metrics ---
    from analysis.metrics_analyzer import MetricsAnalyzer
    
    analyzer = MetricsAnalyzer()
    metrics = analyzer.analyze(facts)
    
    # --- Phase 3: Run rules against facts ---
    await manager.update_progress(job_id, 55.0, "analyzing")
    token.check()
    
    # Create rule engine with ruleset
    rule_engine = create_engine(ruleset=ruleset)
    
    # Progress callback for rule execution - maps 55% to 80% range
    def on_rule_progress(fraction: float, rules_done: int, rules_total: int):
        # Map rule progress (0-1) to progress range (55-80)
        pct = 55.0 + fraction * 25.0
        asyncio.run_coroutine_threadsafe(
            manager.update_progress(
                job_id,
                pct,
                "analyzing",
                current_file=f"Rule {rules_done}/{rules_total}",
                files_processed=rules_done,
                files_total=rules_total,
            ),
            loop
        )
    
    # Run rules with progress callback
    engine_result = await asyncio.to_thread(
        rule_engine.run,
        facts,
        metrics,  # Pass computed metrics
        project_info.project_type.value,
        token.is_cancelled,
        differential_mode,
        set(changed_files or []),
        on_rule_progress,
    )
    token.check()
    
    await manager.update_progress(job_id, 80.0, "analyzing")
    
    # --- Phase 4 & 5: Calculate scores and Generate Report ---
    await manager.update_progress(job_id, 85.0, "scoring")
    token.check()
    
    scoring_engine = ScoringEngine(ruleset)
    report = await asyncio.to_thread(
        scoring_engine.generate_report,
        job_id=job_id or f"scan_{uuid.uuid4().hex[:12]}",
        project_path=project_path,
        findings=engine_result.findings,
        facts=facts,
        project_info=project_info,
        ruleset_path=str(ruleset_path) if ruleset_path else None,
        rules_executed=rule_engine.get_rule_ids(),
    )

    # Phase 11: compute UI hotspots from derived metrics/facts (do not change scoring behavior).
    try:
        from schemas.report import ComplexityHotspot, DuplicationHotspot

        method_by_fqn = {m.method_fqn: m for m in getattr(facts, "methods", []) or []}
        hotspots: list[ComplexityHotspot] = []
        for mm in (metrics or {}).values():
            if not mm:
                continue
            mi = method_by_fqn.get(getattr(mm, "method_fqn", "") or "")
            if not mi:
                continue
            hotspots.append(
                ComplexityHotspot(
                    method_fqn=mm.method_fqn,
                    file=mm.file_path,
                    line_start=int(getattr(mi, "line_start", 1) or 1),
                    loc=int(getattr(mi, "loc", 0) or 0),
                    cyclomatic=int(getattr(mm, "cyclomatic_complexity", 1) or 1),
                    cognitive=int(getattr(mm, "cognitive_complexity", 1) or 1),
                    nesting_depth=int(getattr(mm, "nesting_depth", 0) or 0),
                )
            )

        hotspots.sort(key=lambda h: (-h.cognitive, -h.cyclomatic, h.method_fqn))
        report.complexity_hotspots = hotspots[:10]

        dup_raw = getattr(facts, "_duplication", None)
        dup_hs: list[DuplicationHotspot] = []
        if isinstance(dup_raw, dict):
            for fp, data in dup_raw.items():
                if not isinstance(data, dict):
                    continue
                try:
                    pct = float(data.get("duplication_pct", 0.0) or 0.0)
                except Exception:
                    pct = 0.0
                if pct <= 0:
                    continue
                dup_hs.append(
                    DuplicationHotspot(
                        file=str(fp),
                        duplication_pct=float(pct),
                        duplicated_tokens=int(data.get("duplicated_tokens", 0) or 0),
                        total_tokens=int(data.get("total_tokens", 0) or 0),
                        duplicate_blocks=int(data.get("duplicate_blocks", 0) or 0),
                    )
                )

        dup_hs.sort(key=lambda d: (-d.duplication_pct, -d.duplicated_tokens, d.file))
        report.duplication_hotspots = dup_hs[:10]
    except Exception:
        pass
    
    # Update duration
    report.duration_ms = round((time.perf_counter() - start_time) * 1000)

    # Phase 10: baseline delta ("new issues since last scan") persisted per project in app data.
    try:
        from core.baseline import update_report_baseline_metadata

        profile_for_baseline = (baseline_profile or getattr(ruleset, "name", "startup") or "startup").strip()
        baseline_diff = update_report_baseline_metadata(report, profile=profile_for_baseline)
    except Exception:
        baseline_diff = None

    # Optional PR mode: evaluate gate directly on new regressions vs baseline.
    if pr_mode:
        try:
            from core.pr_gate import evaluate_pr_gate

            gate = evaluate_pr_gate(
                report,
                preset_name=pr_gate_preset or getattr(ruleset, "name", "startup"),
                profile=profile_for_baseline if "profile_for_baseline" in locals() else None,
                baseline_diff=baseline_diff,
            )
            setattr(
                report,
                "pr_gate",
                {
                    "preset": gate.preset,
                    "profile": gate.profile,
                    "passed": gate.passed,
                    "reason": gate.reason,
                    "baseline_has_previous": gate.baseline_has_previous,
                    "baseline_path": gate.baseline_path,
                    "total_new_findings": gate.total_new_findings,
                    "eligible_new_findings": gate.eligible_new_findings,
                    "blocking_findings_count": gate.blocking_findings_count,
                    "blocking_fingerprints": list(gate.blocking_fingerprints),
                    "by_severity": dict(gate.by_severity),
                    "by_rule": dict(gate.by_rule),
                },
            )
        except Exception:
            pass
    
    return report


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
    diff: str


@router.get("/scan/{job_id}/fixes")
async def get_fix_suggestions(job_id: str):
    """Get auto-fix suggestions for all findings."""
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    
    try:
        from core.auto_fix import AutoFixEngine
        
        engine = AutoFixEngine()
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
        
        engine = AutoFixEngine()
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
        
        engine = AutoFixEngine()
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
        
        if not fix.auto_applicable and not dry_run:
            raise HTTPException(status_code=400, detail="This fix requires manual review")
        
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
        import hashlib
        
        manager = ScanHistoryManager()
        project_hash = hashlib.sha256(report.project_path.encode()).hexdigest()[:16]
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
        import hashlib
        
        manager = ScanHistoryManager()
        project_hash = hashlib.sha256(report.project_path.encode()).hexdigest()[:16]
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
        import hashlib
        
        manager = ScanHistoryManager()
        project_hash = hashlib.sha256(report.project_path.encode()).hexdigest()[:16]
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
