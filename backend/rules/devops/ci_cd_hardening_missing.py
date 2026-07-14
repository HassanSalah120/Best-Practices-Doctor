"""
CI/CD Hardening Missing Rule

Scans CI workflow files for common Laravel/React project quality and security
steps. Flags when a project has CI workflows but is missing fundamental gates:
Pint, Rector, PHPUnit, Playwright, composer audit, npm audit.

Uses a scoring approach — missing 3+ of 6 recommended steps triggers a finding.
"""

from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class CiCdHardeningMissingRule(Rule):
    id = "ci-cd-hardening-missing"
    name = "CI/CD Hardening Missing"
    description = "Detects CI workflows missing fundamental quality and security gates"
    category = Category.OPERATIONS
    default_severity = Severity.MEDIUM
    type = "regex"
    severity_weight = 5
    confidence = "high"
    fix_suggestion = (
        "Add the following gates to your CI workflow(s):\n"
        "1. `composer audit` — checks for known vulnerable PHP dependencies\n"
        "2. `npm audit` — checks for known vulnerable JS dependencies\n"
        "3. `./vendor/bin/pint` or `pint` — enforces Laravel/PHP code style\n"
        "4. `rector` or `rector process` — detects unsafe/legacy PHP patterns\n"
        "5. `phpunit` or `pest` — runs the test suite\n"
        "6. `playwright` — runs end-to-end browser tests (if React frontend)"
    )
    examples = {}
    priority = 2
    group = "DevOps"
    applies_to = ["config"]
    references = []
    related_rules = ["tests-missing"]
    false_positive_notes = (
        "Minimal CI setups or projects using alternative tools (phplint, eslint, etc.) "
        "may be intentionally missing some of these gates. This rule scores by count, "
        "so a project with 2 of 6 gates will not trigger."
    )
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "general", "type": "quality", "concern": "ci-cd-gates"}

    _CI_FILE_PATTERN = re.compile(r"(\.github/workflows/|\.gitlab-ci|Jenkinsfile|azure-pipelines|circleci)", re.IGNORECASE)
    _GATES: list[tuple[str, re.Pattern, str]] = [
        ("composer_audit", re.compile(r"\bcomposer\s+audit\b", re.IGNORECASE), "Composer audit"),
        ("npm_audit", re.compile(r"\bnpm\s+audit\b", re.IGNORECASE), "NPM audit"),
        ("pint", re.compile(r"\b(\./vendor/bin/pint|pint\b)", re.IGNORECASE), "Pint (code style)"),
        ("rector", re.compile(r"\b(rector|rector\.phar)\b", re.IGNORECASE), "Rector (refactoring)"),
        ("phpunit", re.compile(r"\b(phpunit|pest)\b", re.IGNORECASE), "PHPUnit/Pest (tests)"),
        ("playwright", re.compile(r"\bplaywright\b", re.IGNORECASE), "Playwright (E2E)"),
    ]

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
        if not self._CI_FILE_PATTERN.search(norm):
            return []
        if not (norm.endswith(".yml") or norm.endswith(".yaml") or norm.endswith(".jenkinsfile") or norm.rstrip("/").endswith("jenkinsfile")):
            return []

        found: set[str] = set()
        for gate_id, pattern, _label in self._GATES:
            if pattern.search(content):
                found.add(gate_id)

        total = len(self._GATES)
        present = len(found)
        missing = total - present

        min_missing = int(self.get_threshold("min_missing_gates", 3) or 3)
        if missing < min_missing:
            return []

        missing_labels = [label for gate_id, _pat, label in self._GATES if gate_id not in found]
        has_react = any(
            str(f).lower().endswith((".jsx", ".tsx"))
            for f in (getattr(facts, "files", []) or [])
        )

        why = (
            f"CI workflow at `{file_path}` is missing {missing}/{total} recommended gates: "
            f"{', '.join(missing_labels)}."
        )
        if has_react:
            why += " This project has React frontend files — Playwright E2E tests are especially important."

        return [
            self.create_finding(
                title="CI workflow missing quality/security gates",
                context=f"{file_path}: {missing}/{total} gates missing",
                file=file_path,
                line_start=1,
                description=why,
                why_it_matters=(
                    "Without automated quality and security gates in CI, regressions, "
                    "coding standard violations, and known-vulnerability dependencies "
                    "can reach production undetected."
                ),
                suggested_fix=self.fix_suggestion,
                confidence=0.85,
                tags=["devops", "ci", "quality_gate", "security"],
                evidence_signals=[
                    f"ci_file={file_path}",
                    f"gates_found={present}/{total}",
                    f"missing_gates={','.join(missing_labels)}" if missing_labels else "all_gates_present",
                ],
            ),
        ]
