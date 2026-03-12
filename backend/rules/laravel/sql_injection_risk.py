"""
SQL Injection Risk Rule

Detects raw SQL queries with potential variable interpolation.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class SqlInjectionRiskRule(Rule):
    id = "sql-injection-risk"
    name = "SQL Injection Risk Detection"
    description = "Detects raw SQL queries with potential variable interpolation"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]
    regex_file_extensions = [".php"]

    # Raw SQL methods
    _RAW_SQL_PATTERNS = [
        re.compile(r"DB::raw\s*\(\s*['\"]", re.IGNORECASE),
        re.compile(r"DB::select\s*\(\s*['\"]", re.IGNORECASE),
        re.compile(r"DB::statement\s*\(\s*['\"]", re.IGNORECASE),
        re.compile(r"DB::unprepared\s*\(\s*['\"]", re.IGNORECASE),
        re.compile(r"->whereRaw\s*\(\s*['\"]", re.IGNORECASE),
        re.compile(r"->orWhereRaw\s*\(\s*['\"]", re.IGNORECASE),
        re.compile(r"->havingRaw\s*\(\s*['\"]", re.IGNORECASE),
        re.compile(r"->orderByRaw\s*\(\s*['\"]", re.IGNORECASE),
        re.compile(r"->groupByRaw\s*\(\s*['\"]", re.IGNORECASE),
        re.compile(r"->selectRaw\s*\(\s*['\"]", re.IGNORECASE),
        re.compile(r"->fromRaw\s*\(\s*['\"]", re.IGNORECASE),
        re.compile(r"->joinRaw\s*\(\s*['\"]", re.IGNORECASE),
    ]

    # Variable interpolation patterns (dangerous)
    _VARIABLE_PATTERNS = [
        re.compile(r"\$[a-zA-Z_][a-zA-Z0-9_]*"),  # $variable
        re.compile(r"\{?\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\}?"),  # {$var} or $var
        re.compile(r"->"),  # Property access like $request->id
    ]

    # Safe patterns (parameterized)
    _SAFE_PATTERNS = [
        re.compile(r"\?\s*\)"),  # Parameterized with ?
        re.compile(r":[a-zA-Z_][a-zA-Z0-9_]*\s*[\),]"),  # Named params :name
    ]

    _ALLOWLIST_PATHS = (
        "/tests/",
        "/test/",
        "/vendor/",
        "/database/migrations/",
    )

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
        findings: list[Finding] = []

        # Skip allowlisted paths
        norm_path = (file_path or "").replace("\\", "/").lower()
        if any(allow in norm_path for allow in self._ALLOWLIST_PATHS):
            return findings

        lines = content.split("\n")

        for i, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                continue

            # Check for raw SQL method
            raw_sql_match = None
            for pattern in self._RAW_SQL_PATTERNS:
                match = pattern.search(line)
                if match:
                    raw_sql_match = match
                    break

            if not raw_sql_match:
                continue

            # Check for variable interpolation
            has_variable = any(pattern.search(line) for pattern in self._VARIABLE_PATTERNS)
            if not has_variable:
                continue

            # Check if it's using parameterized queries (safe)
            has_safe_pattern = any(pattern.search(line) for pattern in self._SAFE_PATTERNS)
            if has_safe_pattern:
                continue

            # Extract context
            context = line.strip()[:100]

            findings.append(
                self.create_finding(
                    title="Potential SQL injection via raw query",
                    context=context,
                    file=file_path,
                    line_start=i,
                    description=(
                        f"Detected raw SQL query with potential variable interpolation. "
                        "This pattern can lead to SQL injection if user input is not properly sanitized."
                    ),
                    why_it_matters=(
                        "SQL injection is one of the most critical web application vulnerabilities:\n"
                        "- OWASP Top 10 #3: Injection\n"
                        "- Can lead to data theft, data corruption, or complete system compromise\n"
                        "- May bypass authentication and authorization\n"
                        "- Can be exploited even through indirect user input"
                    ),
                    suggested_fix=(
                        "1. Use parameterized queries:\n"
                        "   DB::select('SELECT * FROM users WHERE id = ?', [$id]);\n\n"
                        "2. Use Eloquent instead of raw SQL:\n"
                        "   User::where('id', $id)->first();\n\n"
                        "3. Use whereRaw with bindings:\n"
                        "   ->whereRaw('id = ?', [$id])\n\n"
                        "4. Never interpolate variables directly in SQL strings"
                    ),
                    code_example=(
                        "// Before (vulnerable)\n"
                        "DB::select(\"SELECT * FROM users WHERE id = $id\");\n"
                        "->whereRaw(\"id = $id\")\n\n"
                        "// After (secure - parameterized)\n"
                        "DB::select('SELECT * FROM users WHERE id = ?', [$id]);\n"
                        "->whereRaw('id = ?', [$id])\n\n"
                        "// Best (use Eloquent)\n"
                        "User::where('id', $id)->first();"
                    ),
                    confidence=0.80,
                    tags=["security", "sql-injection", "owasp-a1", "database"],
                )
            )

        return findings
