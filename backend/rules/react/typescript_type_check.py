"""
TypeScript Type Check Rule

Runs tsc --noEmit to detect TypeScript type errors and syntax issues.
"""

from __future__ import annotations

import os
import re
import subprocess
import logging
from pathlib import Path

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


logger = logging.getLogger(__name__)


class TypeScriptTypeCheckRule(Rule):
    id = "typescript-type-check"
    name = "TypeScript Type Check"
    description = "Detects TypeScript type errors and syntax issues using tsc"
    category = Category.MAINTAINABILITY
    default_severity = Severity.HIGH
    type = "process"  # Special type for external command rules
    applicable_project_types: list[str] = []
    regex_file_extensions: list[str] = []  # Not used for process rules

    # Pattern to parse tsc error output
    # Format: file.ts(line,col): error TSXXXX: message
    _TSC_ERROR_PATTERN = re.compile(
        r"^(?P<file>[^(]+)\((?P<line>\d+),(?P<col>\d+)\):\s*"
        r"(?P<severity>error|warning)\s+(?P<code>TS\d+):\s*(?P<message>.+)$",
        re.MULTILINE
    )

    # Alternative pattern for some tsc outputs
    _TSC_ERROR_PATTERN_ALT = re.compile(
        r"^(?P<file>[^(]+)\((?P<line>\d+),(?P<col>\d+)\):\s*"
        r"(?P<message>.+)$",
        re.MULTILINE
    )

    _ALLOWLIST_PATHS = (
        "/node_modules/",
        "/dist/",
        "/build/",
        "/.next/",
        "/coverage/",
    )

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        """Run tsc --noEmit and parse errors."""
        findings: list[Finding] = []

        # Get project root from facts
        project_root = (
            getattr(facts, "project_path", None)
            or getattr(facts, "project_root", None)
            or os.getcwd()
        )

        project_root = Path(project_root)

        # Check if tsconfig.json exists
        tsconfig = project_root / "tsconfig.json"
        if not tsconfig.exists():
            logger.debug("No tsconfig.json found, skipping TypeScript type check")
            return findings

        # Check if this is a TypeScript project
        has_ts = any(
            (project_root / f).exists()
            for f in ["tsconfig.json", "tsconfig.build.json"]
        )
        if not has_ts:
            return findings

        try:
            # Run tsc --noEmit
            result = subprocess.run(
                ["npx", "tsc", "--noEmit"],
                cwd=str(project_root),
                capture_output=True,
                text=True,
                timeout=120,  # 2 minute timeout
                env={**os.environ, "FORCE_COLOR": "0"}  # Disable colors for parsing
            )

            # Parse errors from stdout and stderr
            output = result.stdout + "\n" + result.stderr

            if not output.strip():
                return findings

            # Parse each error
            for match in self._TSC_ERROR_PATTERN.finditer(output):
                file_path = match.group("file").strip()
                line_num = int(match.group("line"))
                col_num = int(match.group("col"))
                severity_str = match.group("severity")
                code = match.group("code")
                message = match.group("message").strip()

                # Skip allowlisted paths
                if self._is_allowlisted_path(file_path):
                    continue

                # Make path relative to project root
                try:
                    rel_path = str(Path(file_path).relative_to(project_root))
                except ValueError:
                    rel_path = file_path

                severity = Severity.HIGH if severity_str == "error" else Severity.MEDIUM

                findings.append(
                    self.create_finding(
                        title=f"TypeScript {code}: {message}",
                        file=rel_path,
                        line_start=line_num,
                        description=(
                            f"TypeScript {severity_str} {code} at column {col_num}: {message}"
                        ),
                        why_it_matters=(
                            "TypeScript type errors indicate:\n"
                            "- Potential runtime errors\n"
                            "- Incorrect type usage\n"
                            "- Missing type definitions\n"
                            "- API contract violations\n"
                            "Fixing these improves code reliability and IDE support."
                        ),
                        suggested_fix=(
                            f"1. Review the type error at line {line_num}, column {col_num}\n"
                            "2. Check type definitions and interfaces\n"
                            "3. Ensure correct types are used\n"
                            "4. Add missing type annotations if needed\n"
                            "5. Run `npx tsc --noEmit` to verify the fix"
                        ),
                        severity=severity,
                        confidence=1.0,
                        tags=["typescript", "types", "syntax", "tsc"],
                        evidence_signals=[f"tsc_{code}={severity_str}"],
                    )
                )

        except subprocess.TimeoutExpired:
            logger.warning("tsc --noEmit timed out after 120 seconds")
        except FileNotFoundError:
            logger.debug("tsc not found, skipping TypeScript type check")
        except Exception as e:
            logger.warning(f"Error running tsc: {e}")

        return findings

    def _is_allowlisted_path(self, file_path: str) -> bool:
        """Check if path should be skipped."""
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)
