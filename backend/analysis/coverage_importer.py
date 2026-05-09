"""
Coverage Importer

Phase 10: Parse existing coverage artifacts (if present) to enable quality gates.

We do NOT run tests; we only import already-generated reports:
- PHPUnit Clover XML (common paths like clover.xml / build/logs/clover.xml)
- Jest coverage-summary.json (coverage/coverage-summary.json)

The output is a simple mapping of normalized relative file path -> line coverage percent (0-100).
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import xml.etree.ElementTree as ET

from core.path_utils import normalize_rel_path


@dataclass(frozen=True)
class CoverageFile:
    """Coverage info for a single file."""

    pct: float
    total: int | None = None
    covered: int | None = None
    source: str = ""


def _resolve_to_project(project_root: Path, p: str) -> tuple[str | None, Path | None]:
    """Resolve a coverage-reported file path to a normalized project-relative path."""
    if not p:
        return (None, None)

    try:
        raw = Path(p)
        abs_path = raw if raw.is_absolute() else (project_root / raw)
        abs_path = abs_path.resolve()
        rel = abs_path.relative_to(project_root)
    except Exception:
        return (None, None)

    rel_str = normalize_rel_path(str(rel))
    if not rel_str or rel_str.startswith(".."):
        return (None, None)

    return (rel_str, abs_path)


def _parse_phpunit_clover_xml(project_root: Path, xml_path: Path) -> dict[str, CoverageFile]:
    """Parse PHPUnit Clover XML and return rel_path -> CoverageFile."""
    out: dict[str, CoverageFile] = {}

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception:
        return out

    for file_el in root.findall(".//file"):
        name = file_el.get("name") or ""
        rel_str, _abs = _resolve_to_project(project_root, name)
        if not rel_str:
            continue

        total = 0
        covered = 0

        # Clover uses <line type="stmt" count="..."> for line coverage.
        for line_el in file_el.findall("line"):
            ltype = (line_el.get("type") or "").strip().lower()
            if ltype not in {"stmt"}:
                continue
            total += 1
            try:
                cnt = int(line_el.get("count") or "0")
            except Exception:
                cnt = 0
            if cnt > 0:
                covered += 1

        if total <= 0:
            continue

        pct = (covered / total) * 100.0
        out[rel_str] = CoverageFile(pct=float(pct), total=total, covered=covered, source="phpunit")

    return out


def _parse_jest_coverage_summary(project_root: Path, json_path: Path) -> dict[str, CoverageFile]:
    """Parse Jest coverage-summary.json and return rel_path -> CoverageFile."""
    out: dict[str, CoverageFile] = {}

    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except Exception:
        return out

    if not isinstance(data, dict):
        return out

    for key, entry in data.items():
        if key == "total":
            continue
        if not isinstance(entry, dict):
            continue

        rel_str, _abs = _resolve_to_project(project_root, str(key))
        if not rel_str:
            continue

        lines = entry.get("lines") if isinstance(entry.get("lines"), dict) else {}
        pct = lines.get("pct")
        total = lines.get("total")
        covered = lines.get("covered")

        try:
            pct_f = float(pct)
        except Exception:
            continue

        try:
            total_i = int(total) if total is not None else None
        except Exception:
            total_i = None

        try:
            covered_i = int(covered) if covered is not None else None
        except Exception:
            covered_i = None

        out[rel_str] = CoverageFile(pct=pct_f, total=total_i, covered=covered_i, source="jest")

    return out


def _first_existing(project_root: Path, candidates: list[str]) -> Path | None:
    for rel in candidates:
        p = (project_root / rel).resolve()
        if p.exists() and p.is_file():
            return p
    return None


def load_coverage(project_root: str | Path) -> dict[str, CoverageFile]:
    """Load coverage from known locations, returning rel_path -> CoverageFile."""
    root = Path(project_root).resolve()
    if not root.exists():
        return {}

    out: dict[str, CoverageFile] = {}

    # PHPUnit Clover XML candidates.
    php_candidates = [
        "clover.xml",
        "coverage.xml",
        "build/logs/clover.xml",
        "build/logs/coverage.xml",
        "coverage/clover.xml",
        "coverage/coverage.xml",
    ]
    clover_path = _first_existing(root, php_candidates)
    if clover_path:
        out.update(_parse_phpunit_clover_xml(root, clover_path))

    # Jest coverage summary candidates.
    jest_candidates = [
        "coverage/coverage-summary.json",
    ]
    jest_path = _first_existing(root, jest_candidates)
    if jest_path:
        # Prefer Jest for JS/TS; for collisions, keep the higher pct as a safe default.
        jest_map = _parse_jest_coverage_summary(root, jest_path)
        for k, v in jest_map.items():
            if k not in out:
                out[k] = v
            else:
                try:
                    if v.pct > out[k].pct:
                        out[k] = v
                except Exception:
                    pass

    return out

