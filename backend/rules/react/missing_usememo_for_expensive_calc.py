"""
Missing UseMemo for Expensive Calculations Rule

Detects expensive calculations in render without memoization.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class MissingUseMemoForExpensiveCalcRule(Rule):
    id = "missing-usememo-for-expensive-calc"
    name = "Missing UseMemo for Expensive Calculations"
    description = "Detects expensive calculations in render without useMemo memoization"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Patterns indicating expensive operations
    _EXPENSIVE_PATTERNS = [
        # Array methods on potentially large arrays
        re.compile(r"\.\s*filter\s*\([^)]*\)\s*\.\s*map\s*\(", re.IGNORECASE),
        re.compile(r"\.\s*filter\s*\([^)]*\)\s*\.\s*sort\s*\(", re.IGNORECASE),
        re.compile(r"\.\s*sort\s*\([^)]*\)\s*\.\s*map\s*\(", re.IGNORECASE),
        re.compile(r"\.\s*reduce\s*\([^)]+,\s*[^)]+\)", re.IGNORECASE),
        # Nested loops pattern
        re.compile(r"\.forEach\s*\([^)]*\)[^}]*\.forEach\s*\(", re.IGNORECASE),
        # Complex calculations
        re.compile(r"Math\.[a-zA-Z]+\([^)]*Math\.[a-zA-Z]+", re.IGNORECASE),
        # JSON operations
        re.compile(r"JSON\.parse\s*\([^)]+\)", re.IGNORECASE),
        # Regex operations
        re.compile(r"new\s+RegExp\s*\([^)]+\)\s*\.\s*exec", re.IGNORECASE),
        re.compile(r"\.match\s*\(\s*new\s+RegExp", re.IGNORECASE),
        # Date operations
        re.compile(r"new\s+Date\s*\([^)]+\)", re.IGNORECASE),
        # Array.from with mapping
        re.compile(r"Array\.from\s*\([^)]+,\s*[^)]+\)", re.IGNORECASE),
        # Object operations
        re.compile(r"Object\.entries\s*\([^)]+\)\s*\.\s*map", re.IGNORECASE),
        re.compile(r"Object\.keys\s*\([^)]+\)\s*\.\s*filter", re.IGNORECASE),
    ]

    # Patterns that indicate useMemo is being used
    _MEMOIZED_PATTERN = re.compile(r"useMemo\s*\(", re.IGNORECASE)

    # Variable assignment patterns (where expensive calc might be)
    _ASSIGNMENT_PATTERN = re.compile(r"const\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([^;]+);?", re.IGNORECASE)

    _ALLOWLIST_PATHS = (
        "/tests/",
        "/test/",
        "/__tests__/",
        "/node_modules/",
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

        text = content or ""
        lines = text.split("\n")

        # Check if file is a React component
        has_component = (
            "function " in text and "return " in text
        ) or (
            "const " in text and "=>" in text
        ) or (
            "export default function" in text
        ) or (
            "export function" in text
        ) or (
            "return <" in text  # JSX return
        ) or (
            "return (" in text
        )

        if not has_component:
            return findings

        # Track if useMemo is used in the file
        file_has_usememo = bool(self._MEMOIZED_PATTERN.search(text))

        for i, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                continue

            # Skip if line already has useMemo
            if self._MEMOIZED_PATTERN.search(line):
                continue

            # Check for expensive patterns
            detected_pattern = None
            for pattern in self._EXPENSIVE_PATTERNS:
                if pattern.search(line):
                    detected_pattern = self._get_pattern_name(pattern)
                    break

            if not detected_pattern:
                continue

            # Check if this is inside a component (heuristic: check for const assignment)
            is_assignment = self._ASSIGNMENT_PATTERN.search(line)

            # Adjust confidence
            confidence = 0.70
            if is_assignment:
                confidence += 0.10
            if not file_has_usememo:
                confidence += 0.05

            context = line.strip()[:80]

            findings.append(
                self.create_finding(
                    title="Expensive calculation without useMemo",
                    context=context,
                    file=file_path,
                    line_start=i,
                    description=(
                        f"Detected potentially expensive operation `{detected_pattern}` in component render. "
                        "This calculation runs on every render and should be memoized with useMemo."
                    ),
                    why_it_matters=(
                        "Without memoization:\n"
                        "- Expensive calculations run on every render\n"
                        "- Performance degrades with large datasets\n"
                        "- Can cause UI lag and poor user experience\n"
                        "- Wastes CPU cycles on unchanged data\n"
                        "- May cause frame drops in animations"
                    ),
                    suggested_fix=(
                        "1. Wrap expensive calculations in useMemo:\n"
                        "   const result = useMemo(() => {\n"
                        "       return data.filter(...).map(...);\n"
                        "   }, [data]);\n\n"
                        "2. Include all dependencies in the dependency array\n\n"
                        "3. For very expensive operations, consider:\n"
                        "   - Web Workers for CPU-intensive tasks\n"
                        "   - Debouncing rapidly changing inputs\n"
                        "   - Caching results outside the component"
                    ),
                    code_example=(
                        "// Before (recalculates every render)\n"
                        "function UserList({ users, filter }) {\n"
                        "    const filteredUsers = users\n"
                        "        .filter(u => u.name.includes(filter))\n"
                        "        .sort((a, b) => a.name.localeCompare(b.name));\n"
                        "    return <ul>{filteredUsers.map(u => <li key={u.id}>{u.name}</li>)}</ul>;\n"
                        "}\n\n"
                        "// After (memoized - only recalculates when dependencies change)\n"
                        "function UserList({ users, filter }) {\n"
                        "    const filteredUsers = useMemo(() => {\n"
                        "        return users\n"
                        "            .filter(u => u.name.includes(filter))\n"
                        "            .sort((a, b) => a.name.localeCompare(b.name));\n"
                        "    }, [users, filter]);\n"
                        "    return <ul>{filteredUsers.map(u => <li key={u.id}>{u.name}</li>)}</ul>;\n"
                        "}"
                    ),
                    confidence=confidence,
                    tags=["react", "performance", "usememo", "memoization", "hooks"],
                )
            )

        return findings

    def _get_pattern_name(self, pattern: re.Pattern) -> str:
        """Get a human-readable name for the detected pattern."""
        pattern_str = pattern.pattern
        if "filter" in pattern_str and "map" in pattern_str:
            return "filter().map()"
        elif "filter" in pattern_str and "sort" in pattern_str:
            return "filter().sort()"
        elif "sort" in pattern_str and "map" in pattern_str:
            return "sort().map()"
        elif "reduce" in pattern_str:
            return "reduce()"
        elif "forEach" in pattern_str:
            return "nested forEach"
        elif "Math" in pattern_str:
            return "Math calculation"
        elif "JSON.parse" in pattern_str:
            return "JSON.parse()"
        elif "RegExp" in pattern_str:
            return "RegExp operation"
        elif "Date" in pattern_str:
            return "Date operation"
        elif "Array.from" in pattern_str:
            return "Array.from()"
        elif "Object.entries" in pattern_str:
            return "Object.entries().map()"
        elif "Object.keys" in pattern_str:
            return "Object.keys().filter()"
        else:
            return "expensive operation"
