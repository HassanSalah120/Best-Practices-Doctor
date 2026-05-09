"""
Scan Report and Job Status Schema
"""
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from .finding import Finding, FindingClassification, Severity
from .project_type import ProjectInfo


class ScanStatus(StrEnum):
    """Scan job status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanJob(BaseModel):
    """Scan job status for SSE updates."""
    id: str
    status: ScanStatus = ScanStatus.PENDING
    progress: float = 0.0  # 0-100
    current_phase: str = ""  # "detecting", "parsing", "analyzing", "scoring"
    current_file: str | None = None
    files_processed: int = 0
    files_total: int = 0

    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None


class ScoreBreakdown(BaseModel):
    """Score breakdown by category (deprecated, use QualityScores)."""
    overall: float = 100.0
    architecture: float = 100.0
    dry: float = 100.0
    laravel: float = 100.0
    complexity: float = 100.0
    security: float = 100.0
    react: float = 100.0
    maintainability: float = 100.0


class CategoryScore(BaseModel):
    """Score for a single category."""
    category: str
    # When a category has weight 0 in scoring weights, we treat it as "not counted" and
    # return `score=None` so the UI can display N/A instead of a misleading 0%.
    score: float | None = 100.0
    raw_score: float = 100.0
    weight: float = 10.0
    has_weight: bool = True
    finding_count: int = 0


class QualityScores(BaseModel):
    """Complete quality scores with grade."""
    overall: float = 100.0
    grade: str = "A"

    # Category scores
    architecture: float = 100.0
    dry: float = 100.0
    laravel: float = 100.0
    react: float = 100.0
    complexity: float = 100.0
    security: float = 100.0
    maintainability: float = 100.0
    srp: float = 100.0
    validation: float = 100.0
    performance: float = 100.0


class ScanScore(BaseModel):
    """Rule-weighted scan score for the v2 report dashboard."""

    overall: int = 100
    security: int = 100
    performance: int = 100
    architecture: int = 100
    quality: int = 100
    accessibility: int = 100


class FileSummary(BaseModel):
    """Summary of findings for a single file."""
    path: str
    finding_count: int = 0
    issue_count: int = 0  # Alias for finding_count
    highest_severity: Any = None
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0


class ActionItem(BaseModel):
    """A deterministic, actionable recommendation grouping for the user."""

    id: str
    rule_id: str
    category: str

    # Stable content (avoid embedding volatile counts in title)
    title: str
    why_it_matters: str = ""
    suggested_fix: str = ""

    # Prioritization (higher = do sooner)
    priority: float = 0.0
    max_severity: Severity = Severity.LOW
    classification: FindingClassification = FindingClassification.ADVISORY

    # Traceability
    finding_fingerprints: list[str] = Field(default_factory=list)
    files: list[str] = Field(default_factory=list)


class TriageItem(BaseModel):
    """Multi-factor prioritization item for fix planning."""

    id: str
    rule_id: str
    category: str
    title: str
    strategy: str = "risky"  # safe|risky|refactor
    recommendation: str = "schedule_next"  # fix_now|schedule_next|ignore_safely_candidate
    impact: float = 0.0
    risk: float = 0.0
    effort: float = 0.0
    context_multiplier: float = 1.0
    triage_score: float = 0.0
    rationale: str = ""
    max_severity: Severity = Severity.LOW
    classification: FindingClassification = FindingClassification.ADVISORY
    finding_fingerprints: list[str] = Field(default_factory=list)
    files: list[str] = Field(default_factory=list)


class ComplexityHotspot(BaseModel):
    """Method-level complexity hotspot for UI."""

    method_fqn: str
    file: str
    line_start: int = 1
    loc: int = 0
    cyclomatic: int = 1
    cognitive: int = 1
    nesting_depth: int = 0


class DuplicationHotspot(BaseModel):
    """File-level duplication hotspot for UI."""

    file: str
    duplication_pct: float = 0.0
    duplicated_tokens: int = 0
    total_tokens: int = 0
    duplicate_blocks: int = 0


class RouteContractIssue(BaseModel):
    """A route/request/page contract issue discovered by Runtime Contract Guard."""

    id: str
    kind: str
    severity: Severity = Severity.MEDIUM
    category: str = "validation"
    route_method: str = ""
    route_uri: str = ""
    route_name: str | None = None
    controller: str | None = None
    action: str | None = None
    file: str = ""
    line: int = 1
    title: str
    detail: str = ""
    finding_fingerprint: str | None = None
    skipped_reason: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class GeneratedContractTest(BaseModel):
    """Generated Laravel feature-test artifact for a route contract."""

    id: str
    framework: str = "pest"
    route_method: str = ""
    route_uri: str = ""
    route_name: str | None = None
    title: str = ""
    reason: str = ""
    file_name: str = "tests/Feature/RuntimeContractGuardTest.php"
    content: str = ""
    issue_ids: list[str] = Field(default_factory=list)


class RuntimeContractSummary(BaseModel):
    """Runtime Contract Guard report payload."""

    mode: str = "hybrid"
    scope: str = "all"
    routes_total: int = 0
    static_checked: int = 0
    runtime_probed: int = 0
    generated_tests: int = 0
    skipped: dict[str, int] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    issues: list[RouteContractIssue] = Field(default_factory=list)
    generated_test_items: list[GeneratedContractTest] = Field(default_factory=list)


class ScanReport(BaseModel):
    """Complete scan report."""
    id: str
    project_path: str
    project_info: ProjectInfo = Field(default_factory=ProjectInfo)

    # Timing
    scanned_at: datetime = Field(default_factory=datetime.now)
    duration_ms: int = 0

    # Counts
    files_scanned: int = 0
    classes_found: int = 0
    methods_found: int = 0

    # Scores (stable API contract for UI)
    scores: QualityScores = Field(default_factory=QualityScores)

    # Rule metadata v2 score. Additive; `scores` remains the stable legacy contract.
    score: ScanScore = Field(default_factory=ScanScore)

    # Findings
    findings: list[Finding] = Field(default_factory=list)

    # Baseline / Quality Gate
    # "New issues since last scan" is computed by comparing finding.fingerprint sets.
    new_findings_count: int = 0
    new_finding_fingerprints: list[str] = Field(default_factory=list)
    resolved_findings_count: int = 0
    resolved_finding_fingerprints: list[str] = Field(default_factory=list)
    unchanged_findings_count: int = 0
    unchanged_finding_fingerprints: list[str] = Field(default_factory=list)
    baseline_profile: str | None = None
    baseline_path: str | None = None
    baseline_has_previous: bool = False
    baseline_new_counts_by_severity: dict[str, int] = Field(default_factory=dict)
    baseline_resolved_counts_by_severity: dict[str, int] = Field(default_factory=dict)
    baseline_unchanged_counts_by_severity: dict[str, int] = Field(default_factory=dict)

    # Grouped views (computed)
    findings_by_file: dict[str, list[str]] = Field(default_factory=dict)  # file -> finding IDs
    findings_by_category: dict[str, list[str]] = Field(default_factory=dict)  # category -> finding IDs
    findings_by_severity: dict[str, int] = Field(default_factory=dict)  # severity -> count
    findings_by_classification: dict[str, int] = Field(default_factory=dict)  # classification -> count

    # File summaries
    file_summaries: list[FileSummary] = Field(default_factory=list)

    # Recommended actions (derived from findings)
    action_plan: list[ActionItem] = Field(default_factory=list)
    triage_plan: list[TriageItem] = Field(default_factory=list)
    top_5_first: list[str] = Field(default_factory=list)
    safe_to_defer: list[str] = Field(default_factory=list)
    pipeline_cache: dict[str, Any] = Field(default_factory=dict)

    # Human-readable summary
    summary: str = ""

    # Debug-friendly analysis context for explainability.
    analysis_debug: dict[str, Any] = Field(default_factory=dict)

    # Ruleset used
    ruleset_path: str | None = None
    rules_executed: list[str] = Field(default_factory=list)

    # Category breakdown
    category_breakdown: dict[str, CategoryScore] = Field(default_factory=dict)

    # Hotspots (computed in the API layer from derived metrics)
    complexity_hotspots: list[ComplexityHotspot] = Field(default_factory=list)
    duplication_hotspots: list[DuplicationHotspot] = Field(default_factory=list)

    # Optional PR-gate evaluation payload (set when running in PR mode).
    pr_gate: dict[str, Any] | None = None

    # Optional Runtime Contract Guard payload for Laravel route/DTO/Inertia contracts.
    runtime_contracts: RuntimeContractSummary | None = None

    def compute_groups(self) -> None:
        """Compute grouped views from findings."""
        self.findings_by_file.clear()
        self.findings_by_category.clear()
        self.findings_by_severity.clear()
        self.findings_by_classification.clear()

        for finding in self.findings:
            # By file
            if finding.file not in self.findings_by_file:
                self.findings_by_file[finding.file] = []
            self.findings_by_file[finding.file].append(finding.id)

            # By category
            cat = finding.category.value
            if cat not in self.findings_by_category:
                self.findings_by_category[cat] = []
            self.findings_by_category[cat].append(finding.id)

            # By severity
            sev = finding.severity.value
            self.findings_by_severity[sev] = self.findings_by_severity.get(sev, 0) + 1

            # By classification
            classification = finding.classification.value
            self.findings_by_classification[classification] = (
                self.findings_by_classification.get(classification, 0) + 1
            )
