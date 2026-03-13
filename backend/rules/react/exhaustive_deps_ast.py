"""
Exhaustive Dependencies AST Rule

AST-based detection of missing dependencies in useEffect, useCallback, useMemo.
This is the most accurate approach - requires AST to properly track closure variables.
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


class ExhaustiveDepsASTRule(Rule):
    id = "exhaustive-deps-ast"
    name = "Exhaustive Dependencies (AST)"
    description = "AST-based detection of missing dependencies in React hooks"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.HIGH
    type = "ast"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Hooks that require dependency arrays
    _HOOKS_WITH_DEPS = {"useEffect", "useCallback", "useMemo", "useLayoutEffect"}

    # Built-in and global variables to exclude
    _BUILTINS = {
        "console", "window", "document", "Math", "JSON", "Date",
        "Array", "Object", "String", "Number", "Boolean",
        "undefined", "null", "true", "false", "NaN", "Infinity",
        "parseInt", "parseFloat", "isNaN", "isFinite",
        "setTimeout", "setInterval", "clearTimeout", "clearInterval",
        "Promise", "Error", "TypeError", "ReferenceError",
        "fetch", "alert", "confirm", "prompt",
        "localStorage", "sessionStorage", "location", "history",
        "navigator", "performance", "requestAnimationFrame",
        "cancelAnimationFrame", "Proxy", "Reflect", "Map", "Set",
        "WeakMap", "WeakSet", "Symbol", "BigInt",
    }

    # React built-ins
    _REACT_BUILTINS = {
        "useState", "useEffect", "useCallback", "useMemo", "useRef",
        "useContext", "useReducer", "useLayoutEffect", "useImperativeHandle",
        "useDebugValue", "useId", "useTransition", "useDeferredValue",
    }

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
        """AST-based analysis for exhaustive dependencies."""
        findings: list[Finding] = []

        # Parse the file
        analyzer = parse_react_file(content, file_path)
        if not analyzer.tree:
            return findings

        # Find all hook calls with dependency arrays
        hook_calls = self._find_hook_calls(analyzer)

        for hook in hook_calls:
            # Extract dependencies from the dependency array
            declared_deps = hook.get("dependencies", [])

            # Find all variables used in the callback
            used_vars = self._find_used_variables(hook["callback"], analyzer)

            # Find missing dependencies
            missing = self._find_missing_dependencies(used_vars, declared_deps, analyzer)

            if missing:
                findings.append(self._create_finding(hook, missing, file_path))

        return findings

    def _find_hook_calls(self, analyzer: ReactASTAnalyzer) -> list[dict]:
        """Find all hook calls that require dependency arrays."""
        hooks = []

        if not analyzer.tree:
            return hooks

        for node in ast.walk(analyzer.tree):
            if isinstance(node, ast.Call):
                # Check if it's a hook call
                hook_name = None
                if isinstance(node.func, ast.Name):
                    hook_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    # React.useEffect style
                    if node.func.attr in self._HOOKS_WITH_DEPS:
                        hook_name = node.func.attr

                if hook_name and hook_name in self._HOOKS_WITH_DEPS:
                    hook_info = {
                        "name": hook_name,
                        "node": node,
                        "line": node.lineno,
                        "callback": None,
                        "dependencies": [],
                        "deps_node": None,
                    }

                    # Extract callback (first argument)
                    if node.args:
                        hook_info["callback"] = node.args[0]

                        # Extract dependency array (second argument)
                        if len(node.args) >= 2:
                            deps_node = node.args[1]
                            hook_info["deps_node"] = deps_node
                            if isinstance(deps_node, ast.List):
                                hook_info["dependencies"] = self._extract_deps(deps_node)

                    hooks.append(hook_info)

        return hooks

    def _extract_deps(self, deps_node: ast.List) -> list[str]:
        """Extract dependency names from a list node."""
        deps = []
        for elt in deps_node.elts:
            if isinstance(elt, ast.Name):
                deps.append(elt.id)
            elif isinstance(elt, ast.Attribute):
                # e.g., props.foo
                deps.append(self._get_attribute_chain(elt))
            elif isinstance(elt, ast.Call):
                # Could be a computed dependency
                deps.append(ast.unparse(elt))
        return deps

    def _get_attribute_chain(self, node: ast.Attribute) -> str:
        """Get full attribute chain like 'props.user.name'."""
        parts = []

        def walk(n):
            if isinstance(n, ast.Attribute):
                parts.append(n.attr)
                walk(n.value)
            elif isinstance(n, ast.Name):
                parts.append(n.id)

        walk(node)
        return ".".join(reversed(parts))

    def _find_used_variables(self, callback: ast.Node | None, analyzer: ReactASTAnalyzer) -> set[str]:
        """Find all variables used in the callback."""
        if not callback:
            return set()

        used = set()

        # Get all Name nodes with Load context (reading variables)
        for node in ast.walk(callback):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                used.add(node.id)
            elif isinstance(node, ast.Attribute):
                # Get the root variable for property access
                root = self._get_root_variable(node)
                if root:
                    used.add(root)

        return used

    def _get_root_variable(self, node: ast.Attribute) -> str | None:
        """Get the root variable from an attribute chain."""
        current = node.value
        while isinstance(current, ast.Attribute):
            current = current.value

        if isinstance(current, ast.Name):
            return current.id
        return None

    def _find_missing_dependencies(
        self,
        used_vars: set[str],
        declared_deps: list[str],
        analyzer: ReactASTAnalyzer,
    ) -> list[str]:
        """Find variables used but not in dependency array."""
        missing = []

        for var in used_vars:
            # Skip built-ins
            if var in self._BUILTINS:
                continue

            # Skip React hooks
            if var in self._REACT_BUILTINS:
                continue

            # Skip imports (they're stable)
            if var in analyzer.imports:
                continue

            # Skip state setters (setXxx from useState)
            if var.startswith("set") and len(var) > 3 and var[3].isupper():
                continue

            # Skip ref.current (refs are mutable)
            if var == "current":
                continue

            # Check if it's in the dependency array
            is_declared = False
            for dep in declared_deps:
                # Exact match or prefix match (props.foo matches props)
                if dep == var or dep.startswith(f"{var}.") or var.startswith(f"{dep}."):
                    is_declared = True
                    break

            if not is_declared:
                missing.append(var)

        return sorted(missing)

    def _create_finding(
        self,
        hook: dict,
        missing: list[str],
        file_path: str,
    ) -> Finding:
        """Create a finding for missing dependencies."""
        hook_name = hook["name"]
        missing_str = ", ".join(missing[:5])
        if len(missing) > 5:
            missing_str += f" (and {len(missing) - 5} more)"

        # Determine severity based on hook type and missing count
        if hook_name == "useEffect" and len(missing) > 2:
            severity = Severity.HIGH
        elif hook_name in ("useCallback", "useMemo"):
            severity = Severity.MEDIUM
        else:
            severity = Severity.MEDIUM

        # Confidence based on whether deps array exists
        confidence = 0.95 if hook.get("deps_node") else 0.85

        return self.create_finding(
            title=f"Missing dependencies in {hook_name}: {missing_str}",
            context=f"{hook_name} at line {hook['line']}",
            file=file_path,
            line_start=hook["line"],
            description=(
                f"The following variables are used inside `{hook_name}` but not included "
                f"in the dependency array: {missing_str}.\n\n"
                f"This can cause stale closures where the callback uses outdated values, "
                f"leading to bugs that are hard to reproduce."
            ),
            why_it_matters=(
                "Missing dependencies cause:\n"
                "- Stale closures: callback uses old variable values\n"
                "- Inconsistent behavior between renders\n"
                "- Hard-to-debug issues that appear sporadically\n"
                "- React StrictMode may expose some issues\n"
                "- ESLint exhaustive-deps rule would catch this"
            ),
            suggested_fix=self._get_fix_suggestion(hook, missing),
            severity=severity,
            confidence=confidence,
            tags=["react", "hooks", "dependencies", "useeffect", "usecallback", "usememo"],
            evidence_signals=[
                f"hook={hook_name}",
                f"missing_count={len(missing)}",
                f"missing={missing_str}",
            ],
        )

    def _get_fix_suggestion(self, hook: dict, missing: list[str]) -> str:
        """Generate fix suggestion for missing dependencies."""
        hook_name = hook["name"]
        existing_deps = hook.get("dependencies", [])

        # Combine existing and missing
        all_deps = sorted(set(existing_deps + missing))

        deps_str = ", ".join(all_deps)

        return (
            f"Add the missing dependencies to the dependency array:\n\n"
            f"{hook_name}(\n"
            f"  () => {{ /* callback body */ }},\n"
            f"  [{deps_str}]\n"
            f")\n\n"
            f"If a dependency changes too frequently, consider:\n"
            f"1. Using useCallback/useMemo for the dependency itself\n"
            f"2. Using a ref for mutable values that don't need to trigger re-runs\n"
            f"3. Restructuring the code to reduce dependencies"
        )
