"""
Composer Dependency Below Secure Version Rule

Detects Composer dependencies pinned below curated secure minimum versions.
"""

from __future__ import annotations

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule
from rules.laravel._dependency_versioning import (
    COMPOSER_ADVISORIES,
    collect_composer_constraints,
    collect_composer_packages,
    find_line_number,
    is_version_below_minimum,
    parse_json_object,
)


class ComposerDependencyBelowSecureVersionRule(Rule):
    id = "composer-dependency-below-secure-version"
    name = "Composer Dependency Below Secure Version"
    description = "Detects Composer dependencies pinned below curated secure minimum versions"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".json", ".lock"]

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        norm = (file_path or "").replace("\\", "/").lower()
        has_lock = "composer.lock" in {str(f).replace("\\", "/").lower() for f in (facts.files or [])}
        if norm == "composer.json" and has_lock:
            return []
        if norm not in {"composer.lock", "composer.json"}:
            return []

        data = parse_json_object(content)
        if data is None:
            return []

        packages = collect_composer_packages(data) if norm == "composer.lock" else collect_composer_constraints(data)
        findings: list[Finding] = []
        for name, advisory in COMPOSER_ADVISORIES.items():
            version = packages.get(name)
            if not version or not is_version_below_minimum(version, advisory.minimum_version):
                continue

            line = find_line_number(content, name)
            findings.append(
                self.create_finding(
                    title="Composer dependency is below the secure minimum version",
                    context=f"{name}@{version}",
                    file=file_path,
                    line_start=line,
                    description=(
                        f"Detected `{name}` at `{version}`, which is below the curated secure minimum "
                        f"`{advisory.minimum_version}`."
                    ),
                    why_it_matters=advisory.summary,
                    suggested_fix=(
                        f"Upgrade `{name}` to `{advisory.minimum_version}` or newer and re-lock dependencies so "
                        "the deployed version reflects the patched release."
                    ),
                    tags=["security", "dependencies", "composer", name],
                    confidence=0.96,
                    evidence_signals=[f"package={name}", f"version={version}", f"minimum={advisory.minimum_version}"],
                )
            )
        return findings
