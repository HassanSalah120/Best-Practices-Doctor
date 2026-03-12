"""
Baseline Manager

Phase 3 design:
- Deterministic on-disk path in the scanned project:
  `.bpdoctor/baselines/<project_slug>/<profile>.json`
- Snapshot-based baseline (not just fingerprints)
- First-class diff model:
  - new findings (regressions)
  - resolved findings
  - unchanged findings
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from schemas.finding import Finding


_SCHEMA_VERSION = 2
_PROFILE_RE = re.compile(r"[^a-z0-9._-]+", re.IGNORECASE)
_SLUG_RE = re.compile(r"[^a-z0-9._-]+", re.IGNORECASE)


@dataclass(frozen=True)
class BaselineFinding:
    fingerprint: str
    rule_id: str
    severity: str
    category: str
    file: str
    line_start: int
    confidence: float


@dataclass(frozen=True)
class BaselineSnapshot:
    schema_version: int
    project_path: str
    project_slug: str
    profile: str
    report_hash: str
    finding_count: int
    fingerprints: list[str]
    findings: list[BaselineFinding]
    counts_by_severity: dict[str, int]
    counts_by_rule: dict[str, int]
    updated_at: str
    path: str


@dataclass(frozen=True)
class BaselineDiff:
    has_baseline: bool
    baseline_profile: str
    baseline_path: str
    new_fingerprints: list[str]
    resolved_fingerprints: list[str]
    unchanged_fingerprints: list[str]
    new_counts_by_severity: dict[str, int]
    resolved_counts_by_severity: dict[str, int]
    unchanged_counts_by_severity: dict[str, int]


# Backward-compatible state used by older tests/callers.
@dataclass(frozen=True)
class BaselineState:
    project_path: str
    report_hash: str
    fingerprints: list[str]
    updated_at: str


def _normalize_project_path(project_path: str) -> str:
    try:
        p = Path(project_path).resolve()
        s = str(p)
    except Exception:
        s = str(project_path or "")
    return s.replace("\\", "/")


def _safe_name(raw: str, fallback: str) -> str:
    s = str(raw or "").strip().lower()
    s = _PROFILE_RE.sub("-", s).strip("-._")
    return s or fallback


def _project_slug(project_path: str) -> str:
    norm = _normalize_project_path(project_path)
    base = Path(norm).name if norm else "project"
    base = _SLUG_RE.sub("-", str(base).lower()).strip("-._") or "project"
    key = hashlib.sha1(norm.lower().encode("utf-8", errors="ignore")).hexdigest()[:8]
    return f"{base}-{key}"


def _resolve_profile(profile: str | None) -> str:
    return _safe_name(profile or "startup", "startup")


def _baseline_path(project_path: str, profile: str | None = None) -> Path:
    root = Path(project_path).resolve()
    slug = _project_slug(project_path)
    prof = _resolve_profile(profile)
    base_dir = root / ".bpdoctor" / "baselines" / slug
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir / f"{prof}.json"


def _compute_report_hash(fingerprints: list[str]) -> str:
    joined = "\n".join(sorted(set([str(x) for x in (fingerprints or []) if x])))
    return hashlib.sha1(joined.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _severity_key(value: Any) -> str:
    raw = str(getattr(value, "value", value) or "").strip().lower()
    if raw in {"critical", "high", "medium", "low", "info"}:
        return raw
    return "info"


def _category_key(value: Any) -> str:
    return str(getattr(value, "value", value) or "").strip().lower()


def _finding_payload(f: Finding) -> dict[str, Any]:
    return {
        "fingerprint": str(getattr(f, "fingerprint", "") or ""),
        "rule_id": str(getattr(f, "rule_id", "") or ""),
        "severity": _severity_key(getattr(f, "severity", "")),
        "category": _category_key(getattr(f, "category", "")),
        "file": str(getattr(f, "file", "") or ""),
        "line_start": int(getattr(f, "line_start", 1) or 1),
        "confidence": float(getattr(f, "confidence", 0.0) or 0.0),
    }


def _snapshot_from_findings(
    project_path: str,
    profile: str,
    findings: list[Finding] | None,
    *,
    updated_at: str | None = None,
) -> BaselineSnapshot:
    items = [_finding_payload(f) for f in (findings or []) if getattr(f, "fingerprint", "")]
    items.sort(key=lambda x: (x["fingerprint"], x["rule_id"], x["file"], x["line_start"]))
    deduped: dict[str, dict[str, Any]] = {}
    for it in items:
        fp = str(it["fingerprint"])
        if fp and fp not in deduped:
            deduped[fp] = it
    rows = [deduped[k] for k in sorted(deduped.keys())]

    fps = [r["fingerprint"] for r in rows]
    counts_by_severity: dict[str, int] = {}
    counts_by_rule: dict[str, int] = {}
    baseline_findings: list[BaselineFinding] = []
    for r in rows:
        sev = _severity_key(r.get("severity", ""))
        rid = str(r.get("rule_id", "") or "")
        counts_by_severity[sev] = counts_by_severity.get(sev, 0) + 1
        if rid:
            counts_by_rule[rid] = counts_by_rule.get(rid, 0) + 1
        baseline_findings.append(
            BaselineFinding(
                fingerprint=str(r.get("fingerprint", "") or ""),
                rule_id=rid,
                severity=sev,
                category=str(r.get("category", "") or ""),
                file=str(r.get("file", "") or ""),
                line_start=int(r.get("line_start", 1) or 1),
                confidence=float(r.get("confidence", 0.0) or 0.0),
            )
        )

    p = _baseline_path(project_path, profile)
    return BaselineSnapshot(
        schema_version=_SCHEMA_VERSION,
        project_path=_normalize_project_path(project_path),
        project_slug=_project_slug(project_path),
        profile=_resolve_profile(profile),
        report_hash=_compute_report_hash(fps),
        finding_count=len(fps),
        fingerprints=fps,
        findings=baseline_findings,
        counts_by_severity=dict(sorted(counts_by_severity.items())),
        counts_by_rule=dict(sorted(counts_by_rule.items())),
        updated_at=updated_at or datetime.now(timezone.utc).isoformat(),
        path=str(p),
    )


def _snapshot_to_json_dict(state: BaselineSnapshot) -> dict[str, Any]:
    return {
        "schema_version": int(state.schema_version),
        "project_path": state.project_path,
        "project_slug": state.project_slug,
        "profile": state.profile,
        "report_hash": state.report_hash,
        "finding_count": int(state.finding_count),
        "fingerprints": list(state.fingerprints),
        "counts_by_severity": dict(state.counts_by_severity),
        "counts_by_rule": dict(state.counts_by_rule),
        "findings": [
            {
                "fingerprint": f.fingerprint,
                "rule_id": f.rule_id,
                "severity": f.severity,
                "category": f.category,
                "file": f.file,
                "line_start": int(f.line_start),
                "confidence": float(f.confidence),
            }
            for f in state.findings
        ],
        "updated_at": state.updated_at,
    }


def _snapshot_from_json_dict(project_path: str, profile: str, data: dict[str, Any]) -> BaselineSnapshot:
    raw_findings = data.get("findings")
    findings: list[BaselineFinding] = []
    if isinstance(raw_findings, list):
        for r in raw_findings:
            if not isinstance(r, dict):
                continue
            fp = str(r.get("fingerprint", "") or "")
            if not fp:
                continue
            findings.append(
                BaselineFinding(
                    fingerprint=fp,
                    rule_id=str(r.get("rule_id", "") or ""),
                    severity=_severity_key(r.get("severity", "")),
                    category=str(r.get("category", "") or ""),
                    file=str(r.get("file", "") or ""),
                    line_start=int(r.get("line_start", 1) or 1),
                    confidence=float(r.get("confidence", 0.0) or 0.0),
                )
            )

    if not findings:
        raw_fps = data.get("fingerprints")
        fps = [str(x) for x in raw_fps] if isinstance(raw_fps, list) else []
        findings = [
            BaselineFinding(
                fingerprint=fp,
                rule_id="",
                severity="info",
                category="",
                file="",
                line_start=1,
                confidence=0.0,
            )
            for fp in sorted(set([x for x in fps if x]))
        ]

    findings.sort(key=lambda x: x.fingerprint)
    fps = [f.fingerprint for f in findings]
    counts_by_severity: dict[str, int] = {}
    counts_by_rule: dict[str, int] = {}
    for f in findings:
        counts_by_severity[f.severity] = counts_by_severity.get(f.severity, 0) + 1
        if f.rule_id:
            counts_by_rule[f.rule_id] = counts_by_rule.get(f.rule_id, 0) + 1

    p = _baseline_path(project_path, profile)
    return BaselineSnapshot(
        schema_version=int(data.get("schema_version", _SCHEMA_VERSION) or _SCHEMA_VERSION),
        project_path=str(data.get("project_path") or _normalize_project_path(project_path)),
        project_slug=str(data.get("project_slug") or _project_slug(project_path)),
        profile=str(data.get("profile") or _resolve_profile(profile)),
        report_hash=str(data.get("report_hash") or _compute_report_hash(fps)),
        finding_count=int(data.get("finding_count", len(fps)) or len(fps)),
        fingerprints=sorted(set(fps)),
        findings=findings,
        counts_by_severity=dict(sorted(counts_by_severity.items())),
        counts_by_rule=dict(sorted(counts_by_rule.items())),
        updated_at=str(data.get("updated_at") or ""),
        path=str(p),
    )


def load_baseline_snapshot(project_path: str, profile: str | None = None) -> BaselineSnapshot | None:
    p = _baseline_path(project_path, profile)
    if not p.exists():
        return None
    try:
        payload = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    return _snapshot_from_json_dict(project_path, _resolve_profile(profile), payload)


def save_baseline_snapshot(
    project_path: str,
    findings: list[Finding] | None = None,
    *,
    profile: str | None = None,
) -> BaselineSnapshot:
    prof = _resolve_profile(profile)
    state = _snapshot_from_findings(project_path, prof, findings)
    p = _baseline_path(project_path, prof)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(
        json.dumps(_snapshot_to_json_dict(state), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    tmp.replace(p)
    return state


def compare_baseline_snapshot(
    project_path: str,
    findings: list[Finding] | None = None,
    *,
    profile: str | None = None,
) -> BaselineDiff:
    prof = _resolve_profile(profile)
    baseline = load_baseline_snapshot(project_path, prof)
    current = _snapshot_from_findings(project_path, prof, findings, updated_at="")

    if baseline is None:
        return BaselineDiff(
            has_baseline=False,
            baseline_profile=prof,
            baseline_path=str(_baseline_path(project_path, prof)),
            new_fingerprints=[],
            resolved_fingerprints=[],
            unchanged_fingerprints=[],
            new_counts_by_severity={},
            resolved_counts_by_severity={},
            unchanged_counts_by_severity={},
        )

    cur_by_fp = {f.fingerprint: f for f in current.findings}
    prev_by_fp = {f.fingerprint: f for f in baseline.findings}

    new_fps = sorted(set(cur_by_fp.keys()) - set(prev_by_fp.keys()))
    resolved_fps = sorted(set(prev_by_fp.keys()) - set(cur_by_fp.keys()))
    unchanged_fps = sorted(set(cur_by_fp.keys()) & set(prev_by_fp.keys()))

    def _sev_counts(rows: list[BaselineFinding]) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in rows:
            sev = _severity_key(r.severity)
            out[sev] = out.get(sev, 0) + 1
        return dict(sorted(out.items()))

    new_rows = [cur_by_fp[fp] for fp in new_fps if fp in cur_by_fp]
    resolved_rows = [prev_by_fp[fp] for fp in resolved_fps if fp in prev_by_fp]
    unchanged_rows = [cur_by_fp[fp] for fp in unchanged_fps if fp in cur_by_fp]

    return BaselineDiff(
        has_baseline=True,
        baseline_profile=prof,
        baseline_path=baseline.path,
        new_fingerprints=new_fps,
        resolved_fingerprints=resolved_fps,
        unchanged_fingerprints=unchanged_fps,
        new_counts_by_severity=_sev_counts(new_rows),
        resolved_counts_by_severity=_sev_counts(resolved_rows),
        unchanged_counts_by_severity=_sev_counts(unchanged_rows),
    )


def update_report_baseline_metadata(report, profile: str | None = None, *, save_snapshot: bool = True) -> BaselineDiff:
    """Mutate ScanReport metadata from baseline diff and optionally persist baseline snapshot."""
    try:
        project_path = str(getattr(report, "project_path", "") or "")
        findings = list(getattr(report, "findings", []) or [])
    except Exception:
        return BaselineDiff(
            has_baseline=False,
            baseline_profile=_resolve_profile(profile),
            baseline_path="",
            new_fingerprints=[],
            resolved_fingerprints=[],
            unchanged_fingerprints=[],
            new_counts_by_severity={},
            resolved_counts_by_severity={},
            unchanged_counts_by_severity={},
        )

    diff = compare_baseline_snapshot(project_path, findings, profile=profile)

    # Original fields used by current frontend.
    try:
        report.new_finding_fingerprints = list(diff.new_fingerprints)
        report.new_findings_count = len(diff.new_fingerprints)
    except Exception:
        pass

    # Extended metadata (added defensively to avoid tight coupling).
    try:
        setattr(report, "baseline_profile", diff.baseline_profile)
        setattr(report, "baseline_path", diff.baseline_path)
        setattr(report, "baseline_has_previous", diff.has_baseline)
        setattr(report, "resolved_finding_fingerprints", list(diff.resolved_fingerprints))
        setattr(report, "resolved_findings_count", len(diff.resolved_fingerprints))
        setattr(report, "unchanged_finding_fingerprints", list(diff.unchanged_fingerprints))
        setattr(report, "unchanged_findings_count", len(diff.unchanged_fingerprints))
        setattr(report, "baseline_new_counts_by_severity", dict(diff.new_counts_by_severity))
        setattr(report, "baseline_resolved_counts_by_severity", dict(diff.resolved_counts_by_severity))
        setattr(report, "baseline_unchanged_counts_by_severity", dict(diff.unchanged_counts_by_severity))
    except Exception:
        pass

    if save_snapshot:
        try:
            save_baseline_snapshot(project_path, findings, profile=diff.baseline_profile)
        except Exception:
            pass

    return diff


def reset_baseline_to_report(report, profile: str | None = None) -> None:
    """Persist baseline = current report and clear "new issue" metadata on the report object."""
    try:
        project_path = str(getattr(report, "project_path", "") or "")
        findings = list(getattr(report, "findings", []) or [])
    except Exception:
        return

    prof = _resolve_profile(profile)
    try:
        save_baseline_snapshot(project_path, findings, profile=prof)
    except Exception:
        pass

    try:
        report.new_finding_fingerprints = []
        report.new_findings_count = 0
        setattr(report, "baseline_profile", prof)
        setattr(report, "baseline_path", str(_baseline_path(project_path, prof)))
        setattr(report, "baseline_has_previous", True)
        setattr(report, "resolved_finding_fingerprints", [])
        setattr(report, "resolved_findings_count", 0)
        setattr(report, "unchanged_finding_fingerprints", [])
        setattr(report, "unchanged_findings_count", 0)
    except Exception:
        pass


def baseline_diff_from_report(report, profile: str | None = None) -> BaselineDiff:
    """Build BaselineDiff from ScanReport metadata (captured at scan time)."""
    prof = _resolve_profile(profile or getattr(report, "baseline_profile", None))
    try:
        has_prev = bool(getattr(report, "baseline_has_previous", False))
        baseline_path = str(getattr(report, "baseline_path", "") or "")
        new_fps = sorted(set([str(x) for x in (getattr(report, "new_finding_fingerprints", []) or []) if x]))
        resolved_fps = sorted(set([str(x) for x in (getattr(report, "resolved_finding_fingerprints", []) or []) if x]))
        unchanged_fps = sorted(set([str(x) for x in (getattr(report, "unchanged_finding_fingerprints", []) or []) if x]))
        new_by_sev = dict(getattr(report, "baseline_new_counts_by_severity", {}) or {})
        resolved_by_sev = dict(getattr(report, "baseline_resolved_counts_by_severity", {}) or {})
        unchanged_by_sev = dict(getattr(report, "baseline_unchanged_counts_by_severity", {}) or {})
    except Exception:
        has_prev = False
        baseline_path = ""
        new_fps = []
        resolved_fps = []
        unchanged_fps = []
        new_by_sev = {}
        resolved_by_sev = {}
        unchanged_by_sev = {}

    return BaselineDiff(
        has_baseline=has_prev,
        baseline_profile=prof,
        baseline_path=baseline_path,
        new_fingerprints=new_fps,
        resolved_fingerprints=resolved_fps,
        unchanged_fingerprints=unchanged_fps,
        new_counts_by_severity=new_by_sev,
        resolved_counts_by_severity=resolved_by_sev,
        unchanged_counts_by_severity=unchanged_by_sev,
    )


# ---- Backward-compatible APIs ----

def load_baseline(project_path: str, profile: str | None = None) -> BaselineState | None:
    snap = load_baseline_snapshot(project_path, profile=profile)
    if not snap:
        return None
    return BaselineState(
        project_path=snap.project_path,
        report_hash=snap.report_hash,
        fingerprints=list(snap.fingerprints),
        updated_at=snap.updated_at,
    )


def save_baseline(project_path: str, fingerprints: list[str], profile: str | None = None) -> BaselineState:
    # Legacy helper that only has fingerprints (no finding metadata).
    pseudo_findings: list[Finding] = []
    for idx, fp in enumerate(sorted(set([str(x) for x in (fingerprints or []) if x]))):
        pseudo_findings.append(
            Finding(
                rule_id="legacy-baseline",
                fingerprint=fp,
                context=fp,
                title="Legacy baseline record",
                category="maintainability",
                severity="info",
                file=".bpdoctor/legacy",
                line_start=idx + 1,
                description="Legacy baseline fingerprint-only record.",
                why_it_matters="Compatibility data for previous baseline format.",
                suggested_fix="No action needed.",
                confidence=1.0,
            )
        )

    snap = save_baseline_snapshot(project_path, pseudo_findings, profile=profile)
    return BaselineState(
        project_path=snap.project_path,
        report_hash=snap.report_hash,
        fingerprints=list(snap.fingerprints),
        updated_at=snap.updated_at,
    )


def compute_new_issues_since_last_scan(
    project_path: str,
    current_fingerprints: list[str],
    profile: str | None = None,
) -> tuple[list[str], BaselineState | None]:
    prev = load_baseline(project_path, profile=profile)
    cur_set = set([str(x) for x in (current_fingerprints or []) if x])
    prev_set = set(prev.fingerprints) if prev else set()

    # Keep previous behavior for first-run UX: no baseline => no "new issues yet".
    if not prev:
        return ([], None)

    new = sorted(cur_set - prev_set)
    return (new, prev)
