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
        # Chained array methods on potentially large arrays
        re.compile(r"\.\s*filter\s*\([^)]*\)\s*\.\s*map\s*\(", re.IGNORECASE),
        re.compile(r"\.\s*filter\s*\([^)]*\)\s*\.\s*sort\s*\(", re.IGNORECASE),
        re.compile(r"\.\s*sort\s*\([^)]*\)\s*\.\s*map\s*\(", re.IGNORECASE),
        re.compile(r"\.\s*reduce\s*\([^)]+,\s*[^)]+\)", re.IGNORECASE),
        # Nested loops pattern
        re.compile(r"\.forEach\s*\([^)]*\)[^}]*\.forEach\s*\(", re.IGNORECASE),
        # Complex calculations
        re.compile(r"Math\.[a-zA-Z]+\([^)]*Math\.[a-zA-Z]+", re.IGNORECASE),
        # JSON operations on potentially large strings
        re.compile(r"JSON\.parse\s*\([^)]+\)", re.IGNORECASE),
        # Regex operations with exec/test
        re.compile(r"new\s+RegExp\s*\([^)]+\)\s*\.\s*(exec|test)", re.IGNORECASE),
        re.compile(r"\.match\s*\(\s*new\s+RegExp", re.IGNORECASE),
        # Array.from with mapping function
        re.compile(r"Array\.from\s*\([^)]+,\s*[^)]+\)", re.IGNORECASE),
        # Object operations chained with map
        re.compile(r"Object\.entries\s*\([^)]+\)\s*\.\s*map", re.IGNORECASE),
        re.compile(r"Object\.keys\s*\([^)]+\)\s*\.\s*filter", re.IGNORECASE),
    ]

    # Inexpensive patterns that DON'T need useMemo (skip these)
    _INEXPENSIVE_PATTERNS = [
        # Simple Date creation without parsing
        re.compile(r"new\s+Date\s*\(\s*\)", re.IGNORECASE),  # new Date() - just current time
        # Simple array access
        re.compile(r"\[0\]|\[1\]|\[length\s*-\s*1\]", re.IGNORECASE),
        # Simple string operations
        re.compile(r"\.toString\s*\(\s*\)", re.IGNORECASE),
        re.compile(r"\.toLowerCase\s*\(\s*\)", re.IGNORECASE),
        re.compile(r"\.toUpperCase\s*\(\s*\)", re.IGNORECASE),
        re.compile(r"\.trim\s*\(\s*\)", re.IGNORECASE),
        # Simple Math operations (single call, not nested)
        re.compile(r"Math\.(floor|ceil|round|abs|min|max)\s*\(\s*[\w.]+\s*\)", re.IGNORECASE),
        # Simple slice without calculation
        re.compile(r"\.slice\s*\(\s*\d+\s*,?\s*\d*\s*\)", re.IGNORECASE),
        # Simple length check or property access
        re.compile(r"\.length\s*[<>=!]", re.IGNORECASE),
        re.compile(r"\b\w+\.length\b", re.IGNORECASE),  # Just accessing .length property
        # Boolean conversion
        re.compile(r"!![a-zA-Z_]", re.IGNORECASE),
        # Simple ternary
        re.compile(r"\?\s*['\"]?\w+['\"]?\s*:\s*['\"]?\w+['\"]?", re.IGNORECASE),
        # Simple addition/subtraction
        re.compile(r"\b\w+\s*\+\s*['\"]", re.IGNORECASE),  # string + variable
        re.compile(r"\b\w+\s*\+\s*\d+", re.IGNORECASE),  # variable + number
        # Conditional class names (cn, clsx, classNames) - cheap operations
        re.compile(r"cn\s*\(", re.IGNORECASE),
        re.compile(r"clsx\s*\(", re.IGNORECASE),
        re.compile(r"classNames?\s*\(", re.IGNORECASE),
        # Simple includes/indexOf check
        re.compile(r"\.includes\s*\(\s*['\"]", re.IGNORECASE),
        re.compile(r"\.indexOf\s*\(\s*['\"]", re.IGNORECASE),
        # Simple array find on small data
        re.compile(r"\.find\s*\(\s*\w+\s*=>\s*\w+\.[a-zA-Z]+\s*===?\s*['\"]", re.IGNORECASE),
        # Simple some/every checks
        re.compile(r"\.(some|every)\s*\(\s*\w+\s*=>\s*\w+\.[a-zA-Z]+\s*", re.IGNORECASE),
        # Simple filter with basic condition
        re.compile(r"\.filter\s*\(\s*\w+\s*=>\s*\w+\.[a-zA-Z]+\s*===?\s*['\"]", re.IGNORECASE),
        # Template literals with simple variables
        re.compile(r"`[^`]*\$\{\s*\w+\s*\}[^`]*`", re.IGNORECASE),
        # Simple property access chains
        re.compile(r"\b\w+\.[a-zA-Z_]+\.[a-zA-Z_]+\b", re.IGNORECASE),
        # Formatting functions (usually cheap)
        re.compile(r"format[A-Z][a-zA-Z]*\s*\(", re.IGNORECASE),
        re.compile(r"to[A-Z][a-zA-Z]*String\s*\(", re.IGNORECASE),
        re.compile(r"parse[A-Z][a-zA-Z]*\s*\(", re.IGNORECASE),
        # Small object tag/metadata rendering is usually cheap.
        re.compile(r"Object\.entries\s*\(\s*[^)]*\?\?\s*\{\s*\}\s*\)\s*\.\s*map", re.IGNORECASE),
        re.compile(r"Object\.entries\s*\(\s*[^)]*\b(meta|metadata|attrs|attributes|params|query)\b[^)]*\)\s*\.\s*map", re.IGNORECASE),
    ]
    
    # Files that should be excluded (not React components)
    _NON_COMPONENT_FILES = [
        re.compile(r"/utils?/[^/]+\.tsx?$", re.IGNORECASE),  # files in /util/ or /utils/ directory
        re.compile(r"/utilities?/[^/]+\.tsx?$", re.IGNORECASE),  # files in /utility/ or /utilities/ directory
        re.compile(r"/helpers?/[^/]+\.tsx?$", re.IGNORECASE),  # files in /helper/ or /helpers/ directory
        re.compile(r"(^|/)(utils?|helpers?)\.tsx?$", re.IGNORECASE),  # util.ts, utils.ts, helper.ts, helpers.ts
        re.compile(r"(^|/)(utilities?)\.tsx?$", re.IGNORECASE),  # utility.ts, utilities.ts
        re.compile(r"\.utils?\.tsx?$", re.IGNORECASE),  # files ending with .utils.ts or .util.ts
        re.compile(r"\.helpers?\.tsx?$", re.IGNORECASE),  # files ending with .helpers.ts or .helper.ts
        re.compile(r"/hooks/", re.IGNORECASE),
        re.compile(r"/use[A-Z][a-zA-Z]+\.ts$", re.IGNORECASE),  # useXxx.ts hook files
        re.compile(r"/types/", re.IGNORECASE),
        re.compile(r"\.types\.tsx?$", re.IGNORECASE),
        re.compile(r"/constants?/", re.IGNORECASE),
        re.compile(r"/config/", re.IGNORECASE),
        re.compile(r"/i18n/", re.IGNORECASE),
        re.compile(r"/services?/", re.IGNORECASE),
        re.compile(r"/api/", re.IGNORECASE),
        re.compile(r"/scripts?/", re.IGNORECASE),  # Node.js scripts directory
        re.compile(r"\.config\.(js|ts)$", re.IGNORECASE),  # Config files
        re.compile(r"(^|/)check_.*\.js$", re.IGNORECASE),  # Node.js check scripts
    ]

    # Context patterns where memoization is MORE important
    _NEEDS_MEMOIZATION_CONTEXT = [
        re.compile(r"\.map\s*\([^)]*\)\s*=>", re.IGNORECASE),  # Inside a map
        re.compile(r"React\.memo", re.IGNORECASE),  # Passed to memoized component
        re.compile(r"memo\s*\(", re.IGNORECASE),
    ]

    # Patterns that indicate useMemo is being used
    _MEMOIZED_PATTERN = re.compile(r"useMemo\s*\(", re.IGNORECASE)
    
    # Variable assignment patterns (where expensive calc might be)
    _ASSIGNMENT_PATTERN = re.compile(r"const\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([^;]+);?", re.IGNORECASE)
    _JSX_SIGNAL = re.compile(r"return\s*\(\s*<|return\s*<|<\s*[A-Z][A-Za-z0-9_]*|<>\s*", re.MULTILINE)
    _CHAIN_OP_PATTERN = re.compile(r"\.\s*(filter|map|sort|reduce|flatMap|entries|keys|values)\s*\(", re.IGNORECASE)

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
        ext = norm_path.rsplit(".", 1)[-1] if "." in norm_path else ""

        # Skip non-component files (utility files, hooks, types, etc.)
        if any(p.search(norm_path) for p in self._NON_COMPONENT_FILES):
            return findings

        text = content or ""
        lines = text.split("\n")
        has_jsx_signal = bool(self._JSX_SIGNAL.search(text))

        # This rule is about render-time recalculation, so plain TS/JS modules are out of scope.
        if ext in {"ts", "js"} and not has_jsx_signal:
            return findings

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
            has_jsx_signal
        )

        if not has_component:
            return findings

        # Track if useMemo is used in the file
        file_has_usememo = bool(self._MEMOIZED_PATTERN.search(text))
        min_complexity_score = max(2, int(self.get_threshold("min_complexity_score", 3)))
        min_chain_ops = max(1, int(self.get_threshold("min_chain_ops", 2)))
        require_assignment_or_return_context = bool(
            self.get_threshold("require_assignment_or_return_context", True)
        )
        max_findings_per_file = max(1, int(self.get_threshold("max_findings_per_file", 2)))

        memoized_line_ranges = self._find_call_line_ranges(text, "useMemo")
        findings_emitted = 0

        for i, line in enumerate(lines, 1):
            if findings_emitted >= max_findings_per_file:
                break
            # Skip comments
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                continue

            if self._line_in_ranges(i, memoized_line_ranges):
                continue

            # Skip if line already has useMemo
            if self._MEMOIZED_PATTERN.search(line):
                continue

            # Skip inexpensive patterns (simple operations don't need memoization)
            is_inexpensive = any(p.search(line) for p in self._INEXPENSIVE_PATTERNS)
            line_chain_ops = len(self._CHAIN_OP_PATTERN.findall(line))
            if is_inexpensive and line_chain_ops < 2:
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
            is_assignment = bool(self._ASSIGNMENT_PATTERN.search(line))
            is_return_context = stripped.startswith("return ")
            if require_assignment_or_return_context and not (is_assignment or is_return_context):
                continue

            # Check if in a context where memoization matters more
            is_in_critical_context = any(p.search(text[max(0, text.find(line)-100):text.find(line)+100]) for p in self._NEEDS_MEMOIZATION_CONTEXT)
            chain_ops = line_chain_ops
            complexity_score = 0
            if detected_pattern in {"filter().map()", "filter().sort()", "sort().map()", "reduce()", "Object.keys().filter()"}:
                complexity_score += 2
            if detected_pattern in {"reduce()", "JSON.parse()"} and is_assignment:
                complexity_score += 1
            if chain_ops >= min_chain_ops:
                complexity_score += 1
            if is_in_critical_context:
                complexity_score += 1
            if len(line.strip()) >= 90:
                complexity_score += 1
            if file_has_usememo:
                complexity_score -= 1
            if complexity_score < min_complexity_score:
                continue

            # Adjust confidence based on context
            if is_in_critical_context:
                confidence = 0.85  # Higher - in list or memoized component
            elif is_assignment:
                confidence = 0.75  # Good - is being stored in variable
            else:
                confidence = 0.60  # Lower - might be intentional

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
                    evidence_signals=[
                        f"pattern={detected_pattern}",
                        f"chain_ops={chain_ops}",
                        f"complexity_score={complexity_score}",
                        f"in_critical_context={int(is_in_critical_context)}",
                        f"is_assignment={int(is_assignment)}",
                        f"file_has_usememo={int(file_has_usememo)}",
                    ],
                    metadata={
                        "decision_profile": {
                            "detected_pattern": detected_pattern,
                            "chain_ops": chain_ops,
                            "complexity_score": complexity_score,
                            "min_complexity_score": min_complexity_score,
                            "min_chain_ops": min_chain_ops,
                            "is_assignment": is_assignment,
                            "is_return_context": is_return_context,
                            "is_in_critical_context": is_in_critical_context,
                            "file_has_usememo": file_has_usememo,
                        }
                    },
                )
            )
            findings_emitted += 1

        return findings

    def _find_call_line_ranges(self, text: str, call_name: str) -> list[tuple[int, int]]:
        pattern = re.compile(rf"\b{re.escape(call_name)}\s*\(", re.IGNORECASE)
        ranges: list[tuple[int, int]] = []
        for match in pattern.finditer(text):
            paren_start = text.find("(", match.start())
            if paren_start == -1:
                continue
            paren_end = self._find_matching_paren(text, paren_start)
            if paren_end == -1:
                continue
            start_line = text.count("\n", 0, match.start()) + 1
            end_line = text.count("\n", 0, paren_end) + 1
            ranges.append((start_line, end_line))
        return ranges

    def _line_in_ranges(self, line_number: int, ranges: list[tuple[int, int]]) -> bool:
        return any(start <= line_number <= end for start, end in ranges)

    def _find_matching_paren(self, text: str, start: int) -> int:
        depth = 0
        in_single = False
        in_double = False
        in_backtick = False
        in_line_comment = False
        in_block_comment = False
        escaped = False

        for i in range(start, len(text)):
            ch = text[i]
            nxt = text[i + 1] if i + 1 < len(text) else ""

            if in_line_comment:
                if ch == "\n":
                    in_line_comment = False
                continue

            if in_block_comment:
                if ch == "*" and nxt == "/":
                    in_block_comment = False
                continue

            if escaped:
                escaped = False
                continue

            if ch == "\\" and (in_single or in_double or in_backtick):
                escaped = True
                continue

            if in_single:
                if ch == "'":
                    in_single = False
                continue

            if in_double:
                if ch == '"':
                    in_double = False
                continue

            if in_backtick:
                if ch == "`":
                    in_backtick = False
                continue

            if ch == "/" and nxt == "/":
                in_line_comment = True
                continue
            if ch == "/" and nxt == "*":
                in_block_comment = True
                continue

            if ch == "'":
                in_single = True
                continue
            if ch == '"':
                in_double = True
                continue
            if ch == "`":
                in_backtick = True
                continue

            if ch == "(":
                depth += 1
                continue
            if ch == ")":
                depth -= 1
                if depth == 0:
                    return i
                continue

        return -1

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
