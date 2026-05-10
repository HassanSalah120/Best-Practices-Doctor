"""Before/after scan comparison for remediation runs."""

from __future__ import annotations

from schemas.report import ScanReport

from .models import RescanComparison

SCORE_CATEGORIES = ["security", "performance", "architecture", "quality", "accessibility"]
SEVERITIES = ["critical", "high", "medium", "low", "info"]


def compare_scans(
    baseline_report: ScanReport,
    rescan_report: ScanReport,
    run_id: str,
) -> RescanComparison:
    del run_id
    baseline_fps = {str(f.fingerprint) for f in baseline_report.findings}
    rescan_fps = {str(f.fingerprint) for f in rescan_report.findings}
    resolved = sorted(baseline_fps - rescan_fps)
    unchanged = sorted(baseline_fps & rescan_fps)
    new_issues = sorted(rescan_fps - baseline_fps)

    score_delta: dict[str, float] = {}
    for category in SCORE_CATEGORIES:
        baseline_score = float(getattr(getattr(baseline_report, "score", None), category, 0) or 0)
        rescan_score = float(getattr(getattr(rescan_report, "score", None), category, 0) or 0)
        if baseline_score or rescan_score:
            score_delta[category] = rescan_score - baseline_score

    return RescanComparison(
        baseline_scan_id=baseline_report.id,
        rescan_scan_id=rescan_report.id,
        resolved_fingerprints=resolved,
        unchanged_fingerprints=unchanged,
        new_fingerprints=new_issues,
        score_delta=score_delta,
        severity_deltas=_compute_severity_deltas(baseline_report, rescan_report),
    )


def _compute_severity_deltas(baseline_report: ScanReport, rescan_report: ScanReport) -> dict[str, int]:
    baseline = _severity_counts(baseline_report)
    rescan = _severity_counts(rescan_report)
    return {severity: rescan.get(severity, 0) - baseline.get(severity, 0) for severity in SEVERITIES}


def _severity_counts(report: ScanReport) -> dict[str, int]:
    counts = dict.fromkeys(SEVERITIES, 0)
    for finding in report.findings:
        severity = str(getattr(getattr(finding, "severity", ""), "value", getattr(finding, "severity", "")) or "").lower()
        if severity in counts:
            counts[severity] += 1
    return counts
