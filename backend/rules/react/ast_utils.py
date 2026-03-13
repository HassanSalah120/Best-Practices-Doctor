"""
AST Utilities for React Rules

Provides shared AST parsing and analysis utilities for React-specific rules.
Uses Python's ast module for TypeScript/JavaScript parsing via ts-python bridge.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class ComponentInfo:
    """Information about a React component found in AST."""
    name: str
    node: ast.FunctionDef | ast.ArrowFunc
    line_start: int
    line_end: int
    is_arrow_function: bool = False
    props: list[str] = field(default_factory=list)
    state_vars: list[str] = field(default_factory=list)
    hooks: list[HookCall] = field(default_factory=list)
    jsx_returns: list[ast.Node] = field(default_factory=list)
    imports: dict[str, str] = field(default_factory=dict)


@dataclass
class HookCall:
    """Information about a React hook call."""
    name: str
    node: ast.Call
    line: int
    args: list[ast.Node]
    dependencies: list[str] = field(default_factory=list)
    callback_body: ast.Node | None = None


@dataclass
class InlineHandler:
    """Information about an inline event handler."""
    prop_name: str
    node: ast.Node
    line: int
    is_async: bool = False
    has_api_call: bool = False
    has_state_setter: bool = False
    body_complexity: int = 0
    captures_variables: list[str] = field(default_factory=list)


class ReactASTAnalyzer:
    """Analyzes React components using AST for accurate rule detection."""

    # React hook names
    HOOK_NAMES = {
        "useState", "useEffect", "useCallback", "useMemo",
        "useRef", "useContext", "useReducer", "useLayoutEffect",
        "useImperativeHandle", "useDebugValue", "useId",
        "useTransition", "useDeferredValue", "useSyncExternalStore",
    }

    # Event handler prop patterns
    EVENT_HANDLER_PROPS = {
        "onClick", "onChange", "onSubmit", "onFocus", "onBlur",
        "onKeyDown", "onKeyUp", "onKeyPress", "onMouseEnter", "onMouseLeave",
        "onInput", "onSelect", "onReset", "onInvalid",
        "onTouchStart", "onTouchEnd", "onTouchMove",
        "onDrag", "onDragEnd", "onDragStart", "onDrop",
        "onScroll", "onWheel", "onResize", "onClose", "onOpen",
    }

    # State setter pattern
    STATE_SETTER_PATTERN = re.compile(r"^set[A-Z][a-zA-Z0-9]*$")

    def __init__(self, source_code: str, file_path: str = ""):
        self.source_code = source_code
        self.file_path = file_path
        self.tree: ast.Module | None = None
        self.imports: dict[str, str] = {}  # name -> source
        self.components: list[ComponentInfo] = []
        self.parse_errors: list[str] = []

    def parse(self) -> bool:
        """Parse the source code into AST. Returns True if successful."""
        try:
            self.tree = ast.parse(self.source_code)
            self._extract_imports()
            return True
        except SyntaxError as e:
            self.parse_errors.append(f"Syntax error at line {e.lineno}: {e.msg}")
            return False

    def _extract_imports(self) -> None:
        """Extract all imports from the AST."""
        if not self.tree:
            return

        for node in ast.walk(self.tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    name = alias.asname or alias.name
                    self.imports[name] = f"{module}.{alias.name}"
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name
                    self.imports[name] = alias.name

    def has_import(self, name: str) -> bool:
        """Check if a specific import exists."""
        return name in self.imports

    def has_react_import(self) -> bool:
        """Check if React is imported."""
        return any(
            name in self.imports
            for name in ["React", "react"]
        )

    def has_hook_import(self, hook_name: str) -> bool:
        """Check if a specific hook is imported."""
        if hook_name in self.imports:
            return True
        # Check if imported from React
        if self.imports.get(hook_name, "").startswith("react"):
            return True
        return False

    def find_components(self) -> list[ComponentInfo]:
        """Find all React components in the AST."""
        if not self.tree:
            return []

        components = []

        for node in ast.walk(self.tree):
            # Function declaration
            if isinstance(node, ast.FunctionDef):
                if self._is_react_component(node):
                    components.append(self._analyze_component(node))
            # Arrow function assigned to variable
            elif isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Lambda) or self._is_arrow_function(node.value):
                    if self._is_react_component_arrow(node):
                        components.append(self._analyze_arrow_component(node))

        self.components = components
        return components

    def _is_react_component(self, node: ast.FunctionDef) -> bool:
        """Check if a function is a React component."""
        # Must return JSX
        returns_jsx = False
        for child in ast.walk(node):
            if isinstance(child, ast.Return):
                if self._returns_jsx(child.value):
                    returns_jsx = True
                    break

        # Name should be PascalCase
        name = node.name
        is_pascal = name and name[0].isupper()

        return returns_jsx and is_pascal

    def _is_react_component_arrow(self, node: ast.Assign) -> bool:
        """Check if an arrow function assignment is a React component."""
        # Target should be PascalCase
        if not isinstance(node.targets[0], ast.Name):
            return False

        name = node.targets[0].id
        is_pascal = name and name[0].isupper()

        # Must return JSX
        returns_jsx = False
        if self._is_arrow_function(node.value):
            body = node.value.body
            if isinstance(body, ast.Return):
                returns_jsx = self._returns_jsx(body.value)
            elif isinstance(body, list):
                for stmt in body:
                    if isinstance(stmt, ast.Return) and self._returns_jsx(stmt.value):
                        returns_jsx = True
                        break

        return returns_jsx and is_pascal

    def _is_arrow_function(self, node: ast.Node) -> bool:
        """Check if node is an arrow function (lambda in Python AST terms)."""
        # TypeScript arrow functions appear as specific patterns
        return isinstance(node, ast.Lambda) or (
            hasattr(node, "__class__") and "ArrowFunc" in str(node.__class__)
        )

    def _returns_jsx(self, node: ast.Node | None) -> bool:
        """Check if a node returns JSX."""
        if node is None:
            return False

        # Check for JSX-like patterns
        if isinstance(node, ast.Call):
            # React.createElement or similar
            if isinstance(node.func, ast.Name):
                if node.func.id in ("createElement", "jsx", "jsxs"):
                    return True
            # Component instantiation
            if isinstance(node.func, ast.Name):
                if node.func.id[0].isupper():
                    return True

        # Check for dict that looks like JSX props
        if isinstance(node, ast.Dict):
            return True

        return False

    def _analyze_component(self, node: ast.FunctionDef) -> ComponentInfo:
        """Analyze a function component."""
        info = ComponentInfo(
            name=node.name,
            node=node,
            line_start=node.lineno,
            line_end=node.end_lineno or node.lineno,
            is_arrow_function=False,
        )

        # Extract props from parameters
        if node.args.args:
            props_arg = node.args.args[0]
            if isinstance(props_arg, ast.arg):
                # Destructured props
                if hasattr(props_arg, "annotation"):
                    info.props = self._extract_destructured_props(props_arg)

        # Find hooks and state
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                hook_info = self._analyze_hook_call(child)
                if hook_info:
                    info.hooks.append(hook_info)
                    if hook_info.name == "useState":
                        info.state_vars.append(hook_info.dependencies[0] if hook_info.dependencies else "")

        return info

    def _analyze_arrow_component(self, node: ast.Assign) -> ComponentInfo:
        """Analyze an arrow function component."""
        name = node.targets[0].id if isinstance(node.targets[0], ast.Name) else "unknown"

        info = ComponentInfo(
            name=name,
            node=node.value,
            line_start=node.lineno,
            line_end=node.end_lineno or node.lineno,
            is_arrow_function=True,
        )

        # Find hooks in the body
        for child in ast.walk(node.value):
            if isinstance(child, ast.Call):
                hook_info = self._analyze_hook_call(child)
                if hook_info:
                    info.hooks.append(hook_info)

        return info

    def _extract_destructured_props(self, arg: ast.arg) -> list[str]:
        """Extract prop names from destructured parameter."""
        props = []
        # This would need proper TypeScript AST handling
        # For now, return empty - would use ts-python or tree-sitter for real impl
        return props

    def _analyze_hook_call(self, node: ast.Call) -> HookCall | None:
        """Analyze a hook call."""
        if not isinstance(node.func, ast.Name):
            return None

        hook_name = node.func.id
        if hook_name not in self.HOOK_NAMES:
            return None

        info = HookCall(
            name=hook_name,
            node=node,
            line=node.lineno,
            args=node.args,
        )

        # Extract dependencies for useCallback/useMemo/useEffect
        if hook_name in ("useCallback", "useMemo", "useEffect"):
            if len(node.args) >= 2:
                deps_arg = node.args[1]
                if isinstance(deps_arg, ast.List):
                    info.dependencies = [
                        elt.id if isinstance(elt, ast.Name) else ast.unparse(elt)
                        for elt in deps_arg.elts
                    ]
            if node.args:
                info.callback_body = node.args[0]

        return info

    def find_inline_handlers(self) -> list[InlineHandler]:
        """Find all inline event handlers in JSX."""
        handlers = []

        if not self.tree:
            return handlers

        # Look for JSX attribute patterns
        # In Python AST, these appear as keyword arguments or dict keys
        for node in ast.walk(self.tree):
            if isinstance(node, ast.keyword):
                if node.arg and node.arg in self.EVENT_HANDLER_PROPS:
                    handler = self._analyze_handler(node.arg, node.value)
                    if handler:
                        handlers.append(handler)

        return handlers

    def _analyze_handler(self, prop_name: str, value: ast.Node) -> InlineHandler | None:
        """Analyze a handler value."""
        # Check if it's an inline function
        if not self._is_arrow_function(value) and not isinstance(value, ast.Lambda):
            return None

        handler = InlineHandler(
            prop_name=prop_name,
            node=value,
            line=value.lineno if hasattr(value, "lineno") else 0,
        )

        # Analyze the function body
        body = value.body if hasattr(value, "body") else None
        if body:
            handler.body_complexity = self._calculate_complexity(body)
            handler.has_api_call = self._has_api_call(body)
            handler.has_state_setter = self._has_state_setter(body)
            handler.is_async = self._is_async_function(value)
            handler.captures_variables = self._find_captured_variables(value)

        return handler

    def _calculate_complexity(self, node: ast.Node) -> int:
        """Calculate cyclomatic complexity of a node."""
        complexity = 1

        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
            elif isinstance(child, ast.comprehension):
                complexity += 1
                if child.ifs:
                    complexity += len(child.ifs)

        return complexity

    def _has_api_call(self, node: ast.Node) -> bool:
        """Check if node contains API calls."""
        api_patterns = {"fetch", "axios", "ApiClient", "http", "request"}

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    if child.func.id in api_patterns:
                        return True
                if isinstance(child.func, ast.Attribute):
                    if child.func.attr in {"get", "post", "put", "delete", "patch"}:
                        return True

        return False

    def _has_state_setter(self, node: ast.Node) -> bool:
        """Check if node contains state setter calls."""
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    if self.STATE_SETTER_PATTERN.match(child.func.id):
                        return True

        return False

    def _is_async_function(self, node: ast.Node) -> bool:
        """Check if function is async."""
        # Check for async keyword (use getattr since 'async' is reserved)
        return bool(getattr(node, "async", False))

    def _find_captured_variables(self, func_node: ast.Node) -> list[str]:
        """Find variables captured from outer scope."""
        captured = []

        # Get all names used in the function
        used_names = set()
        for node in ast.walk(func_node):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                used_names.add(node.id)

        # Get names defined in the function
        defined_names = set()
        if hasattr(func_node, "body"):
            for node in ast.walk(func_node.body if not isinstance(func_node.body, list) else ast.Module(body=func_node.body)):
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                    defined_names.add(node.id)

        # Parameters are not captured
        params = set()
        if hasattr(func_node, "args"):
            params = {arg.arg for arg in func_node.args.args}

        # Captured = used - defined - params
        captured = list(used_names - defined_names - params)
        return captured

    def find_memoized_components(self) -> list[str]:
        """Find components wrapped with React.memo."""
        memoized = []

        if not self.tree:
            return memoized

        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "memo":
                    if node.args and isinstance(node.args[0], ast.Name):
                        memoized.append(node.args[0].id)
                elif isinstance(node.func, ast.Attribute):
                    if node.func.attr == "memo":
                        if node.args and isinstance(node.args[0], ast.Name):
                            memoized.append(node.args[0].id)

        return memoized

    def find_expensive_calculations(self) -> list[dict]:
        """Find potentially expensive calculations without useMemo."""
        calculations = []

        if not self.tree:
            return calculations

        # Find array method chains
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                # Check for chained methods
                if isinstance(node.func, ast.Attribute):
                    method_name = node.func.attr
                    if method_name in {"filter", "map", "reduce", "sort", "find"}:
                        # Check if parent is also a method call
                        parent_chain = self._get_method_chain(node)
                        if len(parent_chain) >= 2:
                            calculations.append({
                                "node": node,
                                "line": node.lineno,
                                "methods": parent_chain,
                                "is_chained": len(parent_chain) > 1,
                            })

        return calculations

    def _get_method_chain(self, node: ast.Call) -> list[str]:
        """Get the chain of method calls."""
        chain = []

        def walk_call(n):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                chain.append(n.func.attr)
                walk_call(n.func.value)

        walk_call(node)
        return chain


def parse_react_file(source_code: str, file_path: str = "") -> ReactASTAnalyzer:
    """Parse a React file and return an analyzer."""
    analyzer = ReactASTAnalyzer(source_code, file_path)
    analyzer.parse()
    return analyzer


def is_component_memoized(analyzer: ReactASTAnalyzer, component_name: str) -> bool:
    """Check if a component is wrapped with memo."""
    return component_name in analyzer.find_memoized_components()


def get_hook_dependencies(node: ast.Call) -> list[str]:
    """Extract dependencies from a hook call's dependency array."""
    if len(node.args) < 2:
        return []

    deps_arg = node.args[1]
    if not isinstance(deps_arg, ast.List):
        return []

    return [
        elt.id if isinstance(elt, ast.Name) else ast.unparse(elt)
        for elt in deps_arg.elts
    ]
