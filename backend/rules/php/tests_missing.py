"""
Tests Missing Rule (Quality Gate)

Flags projects that have no `tests/` directory or an extremely low number of test files.

This is intentionally conservative and project-level:
- It does not attempt to infer coverage.
- It uses Facts project-level signals (has_tests, test_files_count) populated by FactsBuilder.
"""

from __future__ import annotations

from pathlib import Path

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class TestsMissingRule(Rule):
    id = "tests-missing"
    name = "Tests Missing"
    description = "Detects missing or insufficient automated tests (quality gate)"
    category = Category.MAINTAINABILITY
    default_severity = Severity.MEDIUM

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        # Threshold: how many test files is considered "non-trivial".
        min_test_files = int(self.get_threshold("min_test_files", 3))

        has_tests = bool(getattr(facts, "has_tests", False))
        test_files_count = int(getattr(facts, "test_files_count", 0) or 0)

        if has_tests and test_files_count >= min_test_files:
            return []

        # Anchor to a stable project root file when possible to avoid phantom paths in UI.
        root = Path(getattr(facts, "project_path", "") or ".")
        anchor_candidates = [
            "phpunit.xml",
            "phpunit.xml.dist",
            "pest.php",
            "package.json",
            "composer.json",
            "vitest.config.ts",
            "vitest.config.js",
            "jest.config.ts",
            "jest.config.js",
            "playwright.config.ts",
            "playwright.config.js",
            "cypress.config.ts",
            "cypress.config.js",
            "artisan",
        ]
        anchor = None
        for c in anchor_candidates:
            try:
                if (root / c).exists():
                    anchor = c
                    break
            except Exception:
                continue
        if not anchor:
            # Fallback to any scanned file, otherwise a synthetic root marker.
            try:
                anchor = (facts.files[0] if facts.files else "project")
            except Exception:
                anchor = "project"

        if not has_tests:
            title = "No automated tests detected"
            desc = (
                "No common automated test scaffold was detected "
                "(`tests/`, `__tests__/`, `*.test.*`, `*.spec.*`, or common test config files)."
            )
        else:
            title = "Too few automated tests detected"
            desc = (
                f"Detected a test scaffold, but only {test_files_count} test file(s) were found "
                f"(recommended minimum: {min_test_files})."
            )

        return [
            self.create_finding(
                title=title,
                context="project:test-suite",
                file=str(anchor),
                line_start=1,
                description=desc,
                why_it_matters=(
                    "Without automated tests, refactors are risky and regressions are harder to catch. "
                    "A minimal test suite also enables safe modernization and performance/security improvements."
                ),
                suggested_fix=self._suggested_fix(facts),
                tags=["quality_gate", "testing"],
                confidence=0.9,
            )
        ]

    def _suggested_fix(self, facts: Facts) -> str:
        has_react = bool(getattr(facts, "react_components", [])) or any(
            str(p).lower().endswith((".jsx", ".tsx")) for p in (getattr(facts, "files", []) or [])
        )
        has_php = bool(getattr(facts, "classes", [])) or any(
            str(p).lower().endswith(".php") for p in (getattr(facts, "files", []) or [])
        )

        steps = [
            "1. Add a basic automated test suite for critical user workflows",
            "2. Introduce CI to run tests on every PR",
        ]

        if has_react:
            steps.append(
                "3. For React: use Vitest or Jest with React Testing Library for component and interaction tests"
            )
            steps.append("4. Add Playwright or Cypress for the highest-risk browser flows")
            if has_php:
                steps.append(
                    "5. For Laravel/PHP: use PHPUnit or Pest for feature, integration, and domain-level tests"
                )
            return "\n".join(steps)

        if has_php:
            steps.append(
                "3. For Laravel/PHP: use PHPUnit or Pest and cover controllers/services with integration tests"
            )
            steps.append("4. Add unit tests around pure domain logic and critical edge cases")
            return "\n".join(steps)

        steps.append("3. Add unit tests around pure logic and edge cases in the main runtime modules")
        steps.append("4. Add integration or end-to-end tests for the most important user journeys")
        return "\n".join(steps)
