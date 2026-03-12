"""
Low Coverage Files Rule (Quality Gate)

Flags files whose imported line coverage percentage is below a configured threshold.

Coverage is imported (if present) by MetricsAnalyzer into `facts._coverage` as:
  dict[rel_path, CoverageFile]
"""

from __future__ import annotations

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule
from core.path_utils import normalize_rel_path


class LowCoverageFilesRule(Rule):
    id = "low-coverage-files"
    name = "Low Coverage Files"
    description = "Detects source files with coverage below a minimum threshold (when coverage reports are present)"
    category = Category.MAINTAINABILITY
    default_severity = Severity.MEDIUM

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        cov = getattr(facts, "_coverage", None)
        if not cov or not isinstance(cov, dict):
            return []

        try:
            min_pct = float(self.get_threshold("min_pct", 60.0))
        except Exception:
            min_pct = 60.0

        try:
            max_findings = int(self.get_threshold("max_findings", 50))
        except Exception:
            max_findings = 50

        findings: list[Finding] = []

        # Only consider scanned files so ignore globs apply.
        rel_files = [normalize_rel_path(p) for p in (getattr(facts, "files", []) or [])]
        for rel_path in rel_files:
            if not rel_path:
                continue
            # Only code files we can reasonably expect coverage for.
            lp = rel_path.lower()
            if not (lp.endswith(".php") or lp.endswith(".js") or lp.endswith(".jsx") or lp.endswith(".ts") or lp.endswith(".tsx")):
                continue

            cf = cov.get(rel_path)
            if not cf:
                continue

            try:
                pct = float(getattr(cf, "pct", cf))
            except Exception:
                continue

            if pct >= min_pct:
                continue

            findings.append(
                self.create_finding(
                    title="File coverage is below threshold",
                    context="coverage:below-threshold",
                    file=rel_path,
                    line_start=1,
                    description=(
                        f"File `{rel_path}` has ~{pct:.1f}% line coverage, below the configured minimum of {min_pct:.1f}%."
                    ),
                    why_it_matters=(
                        "Low coverage increases regression risk and makes refactors harder. "
                        "Raising coverage on high-change or high-risk files improves confidence and stability."
                    ),
                    suggested_fix=(
                        "1. Add tests that exercise the file's public behavior (not implementation details)\n"
                        "2. Prefer integration tests for controllers/services and unit tests for pure logic\n"
                        "3. Focus first on files with the highest change rate or critical business impact"
                    ),
                    tags=["quality_gate", "coverage"],
                    confidence=0.8,
                )
            )

            if max_findings and len(findings) >= max_findings:
                break

        return findings

