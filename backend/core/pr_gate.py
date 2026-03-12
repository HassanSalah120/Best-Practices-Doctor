"""
PR Gate Evaluation

Evaluates baseline regressions against policy presets for CI/PR workflows.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import fnmatch

import yaml

from core.baseline import BaselineDiff, compare_baseline_snapshot
from schemas.finding import Finding


_SEVERITY_RANK = {
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


@dataclass(frozen=True)
class PrGatePreset:
    name: str
    description: str = ""
    profile_floor: str = "medium"
    confidence_floor: float = 0.6
    fail_on_new_severities: list[str] = field(default_factory=lambda: ["critical", "high"])
    fail_on_security_regressions: bool = False
    security_min_severity: str = "medium"
    fail_on_profile_floor: bool = False
    allowlisted_paths: list[str] = field(default_factory=list)
    allowlisted_extensions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class PrGateResult:
    preset: str
    profile: str
    passed: bool
    reason: str
    baseline_has_previous: bool
    baseline_path: str
    total_new_findings: int
    eligible_new_findings: int
    blocking_findings_count: int
    blocking_fingerprints: list[str]
    blocking_findings: list[Finding]
    by_severity: dict[str, int]
    by_rule: dict[str, int]


def _normalize_severity(raw: Any) -> str:
    s = str(getattr(raw, "value", raw) or "").strip().lower()
    if s in _SEVERITY_RANK:
        return s
    return "info"


def _severity_ge(a: str, b: str) -> bool:
    return _SEVERITY_RANK.get(_normalize_severity(a), 0) >= _SEVERITY_RANK.get(_normalize_severity(b), 0)


def _norm_path(p: str) -> str:
    return str(p or "").replace("\\", "/")


def _norm_ext(ext: str) -> str:
    s = str(ext or "").strip().lower()
    if not s:
        return ""
    if not s.startswith("."):
        s = "." + s
    return s


def _default_presets() -> dict[str, PrGatePreset]:
    return {
        "startup": PrGatePreset(
            name="startup",
            description="Default low-friction gate: block only new critical/high findings.",
            profile_floor="high",
            confidence_floor=0.7,
            fail_on_new_severities=["critical", "high"],
            fail_on_security_regressions=False,
            fail_on_profile_floor=False,
            allowlisted_paths=[
                "vendor/**",
                "node_modules/**",
                "storage/**",
                "bootstrap/cache/**",
                "tests/**",
                "**/*.stories.*",
                "**/*.story.*",
                "**/storybook/**",
                "**/demo/**",
                "**/demos/**",
            ],
            allowlisted_extensions=[".snap", ".lock", ".min.js", ".min.css"],
        ),
        "balanced": PrGatePreset(
            name="balanced",
            description="Block new critical/high findings and security regressions.",
            profile_floor="medium",
            confidence_floor=0.6,
            fail_on_new_severities=["critical", "high"],
            fail_on_security_regressions=True,
            security_min_severity="medium",
            fail_on_profile_floor=False,
            allowlisted_paths=[
                "vendor/**",
                "node_modules/**",
                "storage/**",
                "bootstrap/cache/**",
                "tests/**",
                "**/*.stories.*",
                "**/*.story.*",
                "**/storybook/**",
                "**/demo/**",
                "**/demos/**",
            ],
            allowlisted_extensions=[".snap", ".lock", ".min.js", ".min.css"],
        ),
        "strict": PrGatePreset(
            name="strict",
            description="Strict gate: block any new finding at or above profile floor.",
            profile_floor="low",
            confidence_floor=0.5,
            fail_on_new_severities=[],
            fail_on_security_regressions=True,
            security_min_severity="low",
            fail_on_profile_floor=True,
            allowlisted_paths=[
                "vendor/**",
                "node_modules/**",
                "storage/**",
                "bootstrap/cache/**",
                "tests/**",
                "**/*.stories.*",
                "**/*.story.*",
                "**/storybook/**",
                "**/demo/**",
                "**/demos/**",
            ],
            allowlisted_extensions=[".snap", ".lock", ".min.js", ".min.css"],
        ),
    }


def _candidate_preset_files() -> list[Path]:
    out: list[Path] = []
    try:
        out.append(Path.cwd() / "pr-gates.yaml")
    except Exception:
        pass
    try:
        backend_root = Path(__file__).resolve().parents[1]
        out.append(backend_root / "pr-gates.yaml")
    except Exception:
        pass
    return out


def _coerce_preset(name: str, raw: dict[str, Any]) -> PrGatePreset:
    fail_sev = raw.get("fail_on_new_severities", [])
    if not isinstance(fail_sev, list):
        fail_sev = []
    fail_sev = [_normalize_severity(x) for x in fail_sev]
    fail_sev = sorted(set([s for s in fail_sev if s in _SEVERITY_RANK]), key=lambda x: _SEVERITY_RANK[x], reverse=True)

    allow_paths = raw.get("allowlisted_paths", [])
    if not isinstance(allow_paths, list):
        allow_paths = []
    allow_paths = [str(x).replace("\\", "/") for x in allow_paths if str(x).strip()]

    allow_exts = raw.get("allowlisted_extensions", [])
    if not isinstance(allow_exts, list):
        allow_exts = []
    allow_exts = [_norm_ext(x) for x in allow_exts]
    allow_exts = [x for x in allow_exts if x]

    try:
        conf = float(raw.get("confidence_floor", 0.6))
    except Exception:
        conf = 0.6
    conf = max(0.0, min(1.0, conf))

    return PrGatePreset(
        name=name,
        description=str(raw.get("description", "") or ""),
        profile_floor=_normalize_severity(raw.get("profile_floor", "medium")),
        confidence_floor=conf,
        fail_on_new_severities=fail_sev,
        fail_on_security_regressions=bool(raw.get("fail_on_security_regressions", False)),
        security_min_severity=_normalize_severity(raw.get("security_min_severity", "medium")),
        fail_on_profile_floor=bool(raw.get("fail_on_profile_floor", False)),
        allowlisted_paths=allow_paths,
        allowlisted_extensions=allow_exts,
    )


def load_pr_gate_presets() -> dict[str, PrGatePreset]:
    defaults = _default_presets()
    payload: dict[str, Any] | None = None

    for p in _candidate_preset_files():
        try:
            if not p.exists():
                continue
            loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            if isinstance(loaded, dict):
                payload = loaded
                break
        except Exception:
            continue

    if not payload:
        return defaults

    raw_presets = payload.get("presets")
    if not isinstance(raw_presets, dict) or not raw_presets:
        return defaults

    merged: dict[str, PrGatePreset] = dict(defaults)
    for name, raw in raw_presets.items():
        n = str(name or "").strip().lower()
        if not n or not isinstance(raw, dict):
            continue
        merged[n] = _coerce_preset(n, raw)
    return merged


def get_pr_gate_preset(name: str | None) -> PrGatePreset:
    presets = load_pr_gate_presets()
    key = str(name or "startup").strip().lower()
    return presets.get(key) or presets.get("startup") or _default_presets()["startup"]


def _is_allowlisted(f: Finding, preset: PrGatePreset) -> bool:
    rel = _norm_path(getattr(f, "file", "") or "")
    low = rel.lower()
    for pat in preset.allowlisted_paths:
        if fnmatch.fnmatch(low, pat.lower()):
            return True

    ext = Path(rel).suffix.lower()
    if ext and ext in {e.lower() for e in preset.allowlisted_extensions}:
        return True
    return False


def evaluate_pr_gate(
    report,
    *,
    preset_name: str | None = None,
    profile: str | None = None,
    baseline_diff: BaselineDiff | None = None,
) -> PrGateResult:
    preset = get_pr_gate_preset(preset_name)
    prof = str(profile or getattr(report, "baseline_profile", "") or preset.name).strip().lower()
    findings: list[Finding] = list(getattr(report, "findings", []) or [])

    if baseline_diff is None:
        baseline_diff = compare_baseline_snapshot(
            str(getattr(report, "project_path", "") or ""),
            findings,
            profile=prof,
        )

    if not baseline_diff.has_baseline:
        return PrGateResult(
            preset=preset.name,
            profile=prof,
            passed=True,
            reason="No previous baseline found; PR gate is informational on first baseline run.",
            baseline_has_previous=False,
            baseline_path=baseline_diff.baseline_path,
            total_new_findings=0,
            eligible_new_findings=0,
            blocking_findings_count=0,
            blocking_fingerprints=[],
            blocking_findings=[],
            by_severity={},
            by_rule={},
        )

    new_set = set(baseline_diff.new_fingerprints)
    total_new = len(new_set)
    if total_new == 0:
        return PrGateResult(
            preset=preset.name,
            profile=prof,
            passed=True,
            reason="No new findings compared with baseline.",
            baseline_has_previous=True,
            baseline_path=baseline_diff.baseline_path,
            total_new_findings=0,
            eligible_new_findings=0,
            blocking_findings_count=0,
            blocking_fingerprints=[],
            blocking_findings=[],
            by_severity={},
            by_rule={},
        )

    eligible: list[Finding] = []
    for f in findings:
        fp = str(getattr(f, "fingerprint", "") or "")
        if not fp or fp not in new_set:
            continue
        conf = float(getattr(f, "confidence", 0.0) or 0.0)
        if conf < preset.confidence_floor:
            continue
        if _is_allowlisted(f, preset):
            continue
        eligible.append(f)

    blocking: list[Finding] = []
    for f in eligible:
        sev = _normalize_severity(getattr(f, "severity", ""))
        cat = str(getattr(getattr(f, "category", ""), "value", getattr(f, "category", "")) or "").strip().lower()

        is_block = False
        if preset.fail_on_new_severities and sev in set(preset.fail_on_new_severities):
            is_block = True
        if preset.fail_on_profile_floor and _severity_ge(sev, preset.profile_floor):
            is_block = True
        if preset.fail_on_security_regressions and cat == "security" and _severity_ge(sev, preset.security_min_severity):
            is_block = True

        if is_block:
            blocking.append(f)

    by_sev: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    for f in blocking:
        sev = _normalize_severity(getattr(f, "severity", ""))
        rid = str(getattr(f, "rule_id", "") or "")
        by_sev[sev] = by_sev.get(sev, 0) + 1
        by_rule[rid] = by_rule.get(rid, 0) + 1

    by_sev = dict(sorted(by_sev.items(), key=lambda kv: _SEVERITY_RANK.get(kv[0], 0), reverse=True))
    by_rule = dict(sorted(by_rule.items(), key=lambda kv: (-kv[1], kv[0])))

    return PrGateResult(
        preset=preset.name,
        profile=prof,
        passed=len(blocking) == 0,
        reason="PR gate passed." if not blocking else "Blocking regressions detected.",
        baseline_has_previous=True,
        baseline_path=baseline_diff.baseline_path,
        total_new_findings=total_new,
        eligible_new_findings=len(eligible),
        blocking_findings_count=len(blocking),
        blocking_fingerprints=sorted({str(getattr(f, "fingerprint", "")) for f in blocking if getattr(f, "fingerprint", "")}),
        blocking_findings=blocking,
        by_severity=by_sev,
        by_rule=by_rule,
    )
