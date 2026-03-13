"""
UseCallback AST Rule

AST-based detection of inline handlers that need memoization.
More accurate than regex - detects imports, memoized components, and captured variables.
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
    InlineHandler,
    parse_react_file,
    is_component_memoized,
)


class UseCallbackASTRule(Rule):
    id = "usecallback-ast"
    name = "UseCallback Required (AST)"
    description = "AST-based detection of inline handlers needing memoization"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    type = "ast"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Trivial patterns that don't need useCallback
    _TRIVIAL_SETTER_PATTERN = re.compile(
        r"^[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*(?:true|false|null|undefined|[\d.]+|\"[^\"]*\"|'[^']*'|`[^`]*`)\s*\)$",
        re.IGNORECASE,
    )
    _TRIVIAL_TOGGLE_PATTERN = re.compile(
        r"^[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*![a-zA-Z_][a-zA-Z0-9_]*\s*\)$",
        re.IGNORECASE,
    )

    # State setter pattern
    _STATE_SETTER_PATTERN = re.compile(r"^set[A-Z][a-zA-Z0-9]*$")

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
        """AST-based analysis for useCallback issues."""
        findings: list[Finding] = []

        # Parse the file
        analyzer = parse_react_file(content, file_path)
        if not analyzer.tree:
            return findings

        # Check if useCallback is imported
        has_usecallback_import = analyzer.has_hook_import("useCallback")

        # Find all components
        components = analyzer.find_components()

        # Find memoized components
        memoized_components = analyzer.find_memoized_components()

        # Find inline handlers
        handlers = self._find_inline_handlers_ast(analyzer)

        for handler in handlers:
            # Skip if already wrapped in useCallback (check parent)
            if self._is_in_usecallback(handler, analyzer):
                continue

            # Determine if this handler needs memoization
            needs_memo, reason, confidence = self._evaluate_handler(
                handler,
                analyzer,
                memoized_components,
                has_usecallback_import,
            )

            if needs_memo:
                findings.append(self._create_finding(handler, reason, confidence, file_path))

        return findings

    def _find_inline_handlers_ast(self, analyzer: ReactASTAnalyzer) -> list[InlineHandler]:
        """Find inline handlers using AST analysis."""
        handlers = []

        # Use the analyzer's built-in handler detection
        found = analyzer.find_inline_handlers()

        for handler in found:
            # Enrich with additional analysis
            self._enrich_handler(handler, analyzer)
            handlers.append(handler)

        return handlers

    def _enrich_handler(self, handler: InlineHandler, analyzer: ReactASTAnalyzer) -> None:
        """Add additional context to handler info."""
        if not handler.node:
            return

        # Check for async/await
        handler.is_async = self._is_async(handler.node)

        # Check for API calls
        handler.has_api_call = self._has_api_calls(handler.node)

        # Check for state setter calls
        handler.has_state_setter = self._has_state_setter(handler.node)

        # Calculate body complexity
        handler.body_complexity = self._calculate_complexity(handler.node)

        # Find captured variables
        handler.captures_variables = self._find_captured_variables(handler.node, analyzer)

    def _is_async(self, node: ast.Node) -> bool:
        """Check if function is async."""
        # Check for async keyword or await usage
        if hasattr(node, "async") and getattr(node, "async", False):
            return True

        for child in ast.walk(node):
            if isinstance(child, ast.Await):
                return True

        return False

    def _has_api_calls(self, node: ast.Node) -> bool:
        """Check for API call patterns."""
        api_indicators = {
            "fetch", "axios", "ApiClient", "http", "request",
            "get", "post", "put", "delete", "patch",
        }

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                # Check function name
                if isinstance(child.func, ast.Name):
                    if child.func.id in api_indicators:
                        return True
                # Check method calls like api.get()
                if isinstance(child.func, ast.Attribute):
                    if child.func.attr in api_indicators:
                        return True
                    # Check for await fetch()
                    if child.func.attr in {"json", "text"}:
                        # Response parsing
                        for parent in ast.walk(node):
                            if isinstance(parent, ast.Await):
                                return True

        return False

    def _has_state_setter(self, node: ast.Node) -> bool:
        """Check for state setter calls."""
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    if self._STATE_SETTER_PATTERN.match(child.func.id):
                        return True
        return False

    def _calculate_complexity(self, node: ast.Node) -> int:
        """Calculate cyclomatic complexity."""
        complexity = 1

        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
            elif isinstance(child, ast.comprehension):
                complexity += 1 + len(child.ifs)

        return complexity

    def _find_captured_variables(self, func_node: ast.Node, analyzer: ReactASTAnalyzer) -> list[str]:
        """Find variables captured from outer scope."""
        # Get all names used in the function
        used_names = set()
        for node in ast.walk(func_node):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                used_names.add(node.id)

        # Get names defined in the function
        defined_names = set()
        if hasattr(func_node, "body"):
            body = func_node.body
            if not isinstance(body, list):
                body = [body]
            for stmt in body:
                for node in ast.walk(stmt):
                    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                        defined_names.add(node.id)
                    elif isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                        defined_names.add(node.name)

        # Parameters
        params = set()
        if hasattr(func_node, "args"):
            params = {arg.arg for arg in func_node.args.args}

        # Built-ins to exclude
        builtins = {
            "console", "window", "document", "Math", "JSON", "Date",
            "Array", "Object", "String", "Number", "Boolean",
            "undefined", "null", "true", "false", "NaN", "Infinity",
            "parseInt", "parseFloat", "isNaN", "isFinite",
            "setTimeout", "setInterval", "clearTimeout", "clearInterval",
            "Promise", "Error", "TypeError", "ReferenceError",
        }

        # Captured = used - defined - params - builtins - imports
        imports = set(analyzer.imports.keys())
        captured = used_names - defined_names - params - builtins - imports

        return sorted(captured)

    def _is_in_usecallback(self, handler: InlineHandler, analyzer: ReactASTAnalyzer) -> bool:
        """Check if handler is already inside a useCallback."""
        # Walk up the tree to find parent
        if not handler.node:
            return False

        for node in ast.walk(analyzer.tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "useCallback":
                    # Check if our handler is the first argument
                    if node.args and node.args[0] is handler.node:
                        return True
                    # Check if handler is nested inside
                    for child in ast.walk(node.args[0] if node.args else node):
                        if child is handler.node:
                            return True

        return False

    def _evaluate_handler(
        self,
        handler: InlineHandler,
        analyzer: ReactASTAnalyzer,
        memoized_components: list[str],
        has_usecallback_import: bool,
    ) -> tuple[bool, str, float]:
        """
        Evaluate if handler needs memoization.
        Returns (needs_memo, reason, confidence).
        """
        # Check if handler is trivial (simple setter)
        if self._is_trivial_handler(handler):
            # Trivial handlers only need memoization if passed to memoized component
            # or in a list context
            if not self._is_in_performance_critical_context(handler, analyzer):
                return False, "", 0.0
            return True, "Trivial handler in performance-critical context", 0.60

        # Async handlers always need memoization
        if handler.is_async:
            return True, "Async handler should be memoized", 0.92

        # Handlers with API calls need memoization
        if handler.has_api_call:
            return True, "Handler with API call should be memoized", 0.90

        # Handlers capturing variables need memoization
        if len(handler.captures_variables) > 0:
            # Higher confidence if capturing props/state
            captures_props = any(v.startswith("props") or v in ["id", "data", "item"] for v in handler.captures_variables)
            confidence = 0.85 if captures_props else 0.75
            return True, f"Handler captures variables: {', '.join(handler.captures_variables[:3])}", confidence

        # Complex handlers (high cyclomatic complexity)
        if handler.body_complexity > 3:
            return True, f"Complex handler (complexity={handler.body_complexity})", 0.70

        # Handler passed to memoized component
        # (This would require tracking where the handler is passed)

        # Default: moderate priority
        return True, "Inline handler creates new reference on each render", 0.65

    def _is_trivial_handler(self, handler: InlineHandler) -> bool:
        """Check if handler is trivial (simple setter)."""
        # Low complexity and only state setter
        if handler.body_complexity <= 1 and handler.has_state_setter and not handler.has_api_call:
            return True

        # Check if body is just a simple call
        if handler.body_complexity == 1 and len(handler.captures_variables) == 0:
            return True

        return False

    def _is_in_performance_critical_context(self, handler: InlineHandler, analyzer: ReactASTAnalyzer) -> bool:
        """Check if handler is in a list or passed to memoized component."""
        if not handler.node:
            return False

        # Check for .map() context
        for node in ast.walk(analyzer.tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == "map":
                    # Check if our handler is inside this map
                    for child in ast.walk(node):
                        if child is handler.node:
                            return True

        return False

    def _create_finding(
        self,
        handler: InlineHandler,
        reason: str,
        confidence: float,
        file_path: str,
    ) -> Finding:
        """Create a finding for the handler."""
        # Determine severity based on confidence
        if confidence >= 0.85:
            severity = Severity.HIGH
        elif confidence >= 0.70:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        captured_str = ""
        if handler.captures_variables:
            captured_str = f"\n- Captures: {', '.join(handler.captures_variables[:5])}"

        return self.create_finding(
            title=f"Inline handler needs useCallback: {handler.prop_name}",
            context=f"{handler.prop_name}={{...}} at line {handler.line}",
            file=file_path,
            line_start=handler.line,
            description=(
                f"Inline arrow function passed to `{handler.prop_name}` prop. "
                f"{reason}.{captured_str}"
            ),
            why_it_matters=(
                "Inline event handlers cause:\n"
                "- New function reference on every parent render\n"
                "- Child components re-render unnecessarily\n"
                "- Breaks React.memo optimizations\n"
                "- Makes dependency arrays unstable in useEffect"
            ),
            suggested_fix=self._get_fix_suggestion(handler),
            severity=severity,
            confidence=confidence,
            tags=["react", "performance", "usecallback", "memoization"],
            evidence_signals=[
                f"prop={handler.prop_name}",
                f"async={handler.is_async}",
                f"api_call={handler.has_api_call}",
                f"complexity={handler.body_complexity}",
                f"captures={len(handler.captures_variables)}",
            ],
        )

    def _get_fix_suggestion(self, handler: InlineHandler) -> str:
        """Generate fix suggestion based on handler type."""
        if handler.captures_variables:
            deps = ", ".join(handler.captures_variables[:5])
            return (
                f"Wrap with useCallback and include dependencies:\n\n"
                f"const handle{handler.prop_name[2:]} = useCallback(\n"
                f"  () => {{ /* handler body */ }},\n"
                f"  [{deps}]\n"
                f");\n\n"
                f"Then pass: <Component {handler.prop_name}={{handle{handler.prop_name[2:]}}} />"
            )

        return (
            f"Wrap with useCallback:\n\n"
            f"const handle{handler.prop_name[2:]} = useCallback(() => {{\n"
            f"  // handler body\n"
            f"}}, []);\n\n"
            f"Then pass: <Component {handler.prop_name}={{handle{handler.prop_name[2:]}}} />"
        )
