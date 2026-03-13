"""
UseMemo AST Rule

AST-based detection of expensive calculations that need memoization.
More accurate than regex - detects chained operations, context, and dependencies.
"""

from __future__ import annotations

import ast
import re
from typing import Any

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule
from rules.react.ast_utils import (
    ReactASTAnalyzer,
    parse_react_file,
)


class UseMemoASTRule(Rule):
    id = "usememo-ast"
    name = "UseMemo Required (AST)"
    description = "AST-based detection of expensive calculations needing memoization"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    type = "ast"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Expensive array method chains
    _EXPENSIVE_CHAINS = [
        {"filter", "map"},
        {"filter", "sort"},
        {"sort", "map"},
        {"reduce"},
        {"flatMap"},
    ]

    # Methods that are O(n) or worse
    _EXPENSIVE_METHODS = {
        "filter", "map", "reduce", "sort", "flatMap", "find", "some", "every",
        "forEach", "entries", "keys", "values", "from",
    }

    # Inexpensive operations that don't need useMemo
    _INEXPENSIVE_OPS = {
        "toString", "toLowerCase", "toUpperCase", "trim", "slice",
        "charAt", "charCodeAt", "includes", "startsWith", "endsWith",
        "indexOf", "lastIndexOf", "concat", "join",
    }

    # Simple Math operations
    _SIMPLE_MATH = {"floor", "ceil", "round", "abs", "min", "max"}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        return []

    def analyze_ast(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        """AST-based analysis for useMemo issues."""
        findings: list[Finding] = []

        # Parse the file
        analyzer = parse_react_file(content, file_path)
        if not analyzer.tree:
            return findings

        # Check if useMemo is imported
        has_usememo_import = analyzer.has_hook_import("useMemo")

        # Find expensive calculations
        calculations = self._find_expensive_calculations(analyzer)

        for calc in calculations:
            # Skip if already in useMemo
            if self._is_in_usememo(calc["node"], analyzer):
                continue

            # Evaluate if this needs memoization
            needs_memo, reason, confidence = self._evaluate_calculation(calc, analyzer)

            if needs_memo:
                findings.append(self._create_finding(calc, reason, confidence, file_path))

        return findings

    def _find_expensive_calculations(self, analyzer: ReactASTAnalyzer) -> list[dict]:
        """Find potentially expensive calculations in the AST."""
        calculations = []

        if not analyzer.tree:
            return calculations

        # Look for method chains on arrays/objects
        for node in ast.walk(analyzer.tree):
            # Check for method call chains
            if isinstance(node, ast.Call):
                chain = self._get_method_chain(node)
                if chain:
                    calc_info = {
                        "node": node,
                        "line": node.lineno,
                        "chain": chain,
                        "is_chained": len(chain) > 1,
                        "methods": chain,
                    }

                    # Check if this is an assignment
                    calc_info["is_assignment"] = self._is_assignment_target(node, analyzer)

                    # Find dependencies (variables used)
                    calc_info["dependencies"] = self._find_dependencies(node, analyzer)

                    # Check context
                    calc_info["in_list_context"] = self._is_in_list_context(node, analyzer)

                    calculations.append(calc_info)

        return calculations

    def _get_method_chain(self, node: ast.Call) -> list[str]:
        """Extract method chain from a call node."""
        chain = []

        def walk_call(n):
            if isinstance(n, ast.Call):
                if isinstance(n.func, ast.Attribute):
                    method = n.func.attr
                    if method in self._EXPENSIVE_METHODS:
                        chain.append(method)
                    # Continue walking up the chain
                    walk_call(n.func.value)
                elif isinstance(n.func, ast.Name):
                    # Function call like Array.from()
                    if n.func.id in {"Array", "Object"}:
                        chain.append(f"{n.func.id}.from")

        walk_call(node)
        return list(reversed(chain))  # Put in execution order

    def _is_assignment_target(self, node: ast.Call, analyzer: ReactASTAnalyzer) -> bool:
        """Check if the call result is assigned to a variable."""
        if not analyzer.tree:
            return False

        for parent in ast.walk(analyzer.tree):
            if isinstance(parent, ast.Assign):
                if parent.value is node:
                    return True
            elif isinstance(parent, ast.AnnAssign):
                if parent.value is node:
                    return True

        return False

    def _find_dependencies(self, node: ast.Call, analyzer: ReactASTAnalyzer) -> list[str]:
        """Find variables that the calculation depends on."""
        dependencies = set()

        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                # Exclude built-ins and imports
                name = child.id
                if name not in {"Math", "JSON", "Date", "Array", "Object", "String", "Number", "Boolean"}:
                    if name not in analyzer.imports:
                        dependencies.add(name)

        return sorted(dependencies)

    def _is_in_list_context(self, node: ast.Call, analyzer: ReactASTAnalyzer) -> bool:
        """Check if calculation is inside a .map() or similar iteration."""
        if not analyzer.tree:
            return False

        # Find parent nodes
        for parent in ast.walk(analyzer.tree):
            if isinstance(parent, ast.Call):
                if isinstance(parent.func, ast.Attribute):
                    if parent.func.attr in {"map", "flatMap", "forEach"}:
                        # Check if our node is inside this iteration
                        for child in ast.walk(parent):
                            if child is node:
                                return True

        return False

    def _is_in_usememo(self, node: ast.Call, analyzer: ReactASTAnalyzer) -> bool:
        """Check if calculation is already inside useMemo."""
        if not analyzer.tree:
            return False

        for parent in ast.walk(analyzer.tree):
            if isinstance(parent, ast.Call):
                if isinstance(parent.func, ast.Name) and parent.func.id == "useMemo":
                    # Check if our node is the first argument's body
                    if parent.args:
                        callback = parent.args[0]
                        for child in ast.walk(callback):
                            if child is node:
                                return True

        return False

    def _evaluate_calculation(
        self,
        calc: dict,
        analyzer: ReactASTAnalyzer,
    ) -> tuple[bool, str, float]:
        """
        Evaluate if calculation needs memoization.
        Returns (needs_memo, reason, confidence).
        """
        chain = calc.get("chain", [])
        is_chained = calc.get("is_chained", False)
        is_assignment = calc.get("is_assignment", False)
        in_list_context = calc.get("in_list_context", False)
        dependencies = calc.get("dependencies", [])

        # Check for expensive method chains
        if is_chained and len(chain) >= 2:
            methods_str = " → ".join(chain)
            confidence = 0.85 if in_list_context else 0.80
            return True, f"Chained array methods: {methods_str}", confidence

        # Single expensive method with dependencies
        if chain and chain[0] in {"reduce", "sort", "flatMap"}:
            confidence = 0.80 if is_assignment else 0.70
            return True, f"Expensive method: {chain[0]}()", confidence

        # filter/map/find with dependencies (might process large arrays)
        if chain and chain[0] in {"filter", "map", "find"}:
            if dependencies:
                # Higher confidence if in list context
                if in_list_context:
                    return True, f"{chain[0]}() in list context with dependencies", 0.75
                elif is_assignment:
                    return True, f"{chain[0]}() with dependencies: {', '.join(dependencies[:3])}", 0.65

        # JSON.parse on potentially large strings
        if "JSON.parse" in chain:
            return True, "JSON.parse() can be expensive for large strings", 0.70

        # Complex nested calls
        nested_count = self._count_nested_calls(calc["node"])
        if nested_count >= 3:
            return True, f"Complex nested operations (depth={nested_count})", 0.70

        return False, "", 0.0

    def _count_nested_calls(self, node: ast.Call) -> int:
        """Count nested call depth."""
        max_depth = 0

        def count_depth(n, depth=0):
            nonlocal max_depth
            if isinstance(n, ast.Call):
                depth += 1
                max_depth = max(max_depth, depth)
                for child in ast.walk(n):
                    if child is not n:
                        count_depth(child, depth)

        count_depth(node)
        return max_depth

    def _create_finding(
        self,
        calc: dict,
        reason: str,
        confidence: float,
        file_path: str,
    ) -> Finding:
        """Create a finding for the calculation."""
        chain = calc.get("chain", [])
        dependencies = calc.get("dependencies", [])

        # Determine severity
        if confidence >= 0.80:
            severity = Severity.HIGH
        elif confidence >= 0.70:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        methods_str = " → ".join(chain) if chain else "calculation"
        deps_str = f"\nDependencies: {', '.join(dependencies[:5])}" if dependencies else ""

        return self.create_finding(
            title=f"Expensive calculation needs useMemo: {methods_str}",
            context=f"line {calc['line']}",
            file=file_path,
            line_start=calc["line"],
            description=(
                f"Potentially expensive operation detected. {reason}.{deps_str}"
            ),
            why_it_matters=(
                "Without memoization:\n"
                "- Expensive calculations run on every render\n"
                "- Performance degrades with large datasets\n"
                "- Can cause UI lag and poor user experience\n"
                "- Wastes CPU cycles on unchanged data"
            ),
            suggested_fix=self._get_fix_suggestion(calc),
            severity=severity,
            confidence=confidence,
            tags=["react", "performance", "usememo", "memoization"],
            evidence_signals=[
                f"methods={' → '.join(chain)}",
                f"is_chained={calc.get('is_chained', False)}",
                f"in_list_context={calc.get('in_list_context', False)}",
                f"dependencies={len(dependencies)}",
            ],
        )

    def _get_fix_suggestion(self, calc: dict) -> str:
        """Generate fix suggestion based on calculation type."""
        chain = calc.get("chain", [])
        dependencies = calc.get("dependencies", [])

        deps_array = ", ".join(dependencies[:5]) if dependencies else ""

        if chain:
            return (
                f"Wrap with useMemo:\n\n"
                f"const result = useMemo(() => {{\n"
                f"  return data.{'. '.join(chain)}(...);\n"
                f"}}, [{deps_array}]);\n\n"
                f"Include all variables from the calculation in the dependency array."
            )

        return (
            f"Wrap with useMemo:\n\n"
            f"const result = useMemo(() => {{\n"
            f"  // expensive calculation\n"
            f"}}, [{deps_array}]);"
        )
