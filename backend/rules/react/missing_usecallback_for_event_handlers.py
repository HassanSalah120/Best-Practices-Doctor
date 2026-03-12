"""
Missing UseCallback for Event Handlers Rule

Detects event handlers passed as props without useCallback memoization.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class MissingUseCallbackForEventHandlersRule(Rule):
    id = "missing-usecallback-for-event-handlers"
    name = "Missing UseCallback for Event Handlers"
    description = "Detects event handlers passed as props without useCallback memoization"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Patterns for event handlers being passed as props
    _HANDLER_PROP_PATTERNS = [
        # Arrow function in JSX prop
        re.compile(r"on[A-Z][a-zA-Z]*=\{\s*\([^)]*\)\s*=>", re.IGNORECASE),
        re.compile(r"on[A-Z][a-zA-Z]*=\{\s*\([^)]*\)\s*=>\s*\{", re.IGNORECASE),
        # Async arrow function in JSX prop (higher priority)
        re.compile(r"on[A-Z][a-zA-Z]*=\{\s*async\s*\([^)]*\)\s*=>", re.IGNORECASE),
        # Anonymous function in JSX prop
        re.compile(r"on[A-Z][a-zA-Z]*=\{\s*function\s*\(", re.IGNORECASE),
        # Inline arrow function with body
        re.compile(r"on[A-Z][a-zA-Z]*=\{\s*\([^)]*\)\s*=>\s*\{[^}]+\}", re.IGNORECASE),
    ]

    # Pattern to detect async handlers (should be higher priority)
    _ASYNC_HANDLER_PATTERN = re.compile(r"on[A-Z][a-zA-Z]*=\{\s*async\s*\(", re.IGNORECASE)

    # Pattern to detect handlers with API calls or complex logic
    _COMPLEX_HANDLER_PATTERNS = [
        re.compile(r"await\s+", re.IGNORECASE),  # async/await
        re.compile(r"fetch\s*\(", re.IGNORECASE),
        re.compile(r"ApiClient\.", re.IGNORECASE),
        re.compile(r"axios\.", re.IGNORECASE),
        re.compile(r"set[A-Z][a-zA-Z]*\s*\(\s*true\s*\)", re.IGNORECASE),  # setLoading(true)
        re.compile(r"set[A-Z][a-zA-Z]*\s*\(\s*false\s*\)", re.IGNORECASE),  # setLoading(false)
    ]

    # Common event handler prop names
    _EVENT_HANDLER_PROPS = {
        "onClick", "onChange", "onSubmit", "onFocus", "onBlur",
        "onKeyDown", "onKeyUp", "onKeyPress", "onMouseEnter", "onMouseLeave",
        "onInput", "onSelect", "onReset", "onInvalid",
        "onTouchStart", "onTouchEnd", "onTouchMove",
        "onDrag", "onDragEnd", "onDragStart", "onDrop",
        "onScroll", "onWheel", "onResize",
    }

    # Patterns indicating useCallback is used
    _USECALLBACK_PATTERN = re.compile(r"useCallback\s*\(", re.IGNORECASE)

    # Pattern for function definitions that could be memoized
    _FUNCTION_DEF_PATTERN = re.compile(
        r"const\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>",
        re.IGNORECASE
    )

    # Props that commonly receive handlers
    _HANDLER_PROP_NAMES = {"handler", "callback", "onAction", "onConfirm", "onClose", "onSave"}

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

        # Check if useCallback is used anywhere in file
        file_has_usecallback = bool(self._USECALLBACK_PATTERN.search(text))

        for i, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                continue

            # Check for inline handler patterns
            for pattern in self._HANDLER_PROP_PATTERNS:
                match = pattern.search(line)
                if match:
                    # Extract the handler prop name
                    prop_match = re.search(r"on[A-Z][a-zA-Z]*", line)
                    prop_name = prop_match.group(0) if prop_match else "handler"

                    # Check if this is a simple handler (no body) - lower severity
                    is_simple = "=>" in line and "{" not in line.split("=>")[1].split(",")[0]

                    # Check for async or complex patterns - HIGHER severity
                    is_async = bool(self._ASYNC_HANDLER_PATTERN.search(line))
                    has_complex_logic = any(p.search(line) for p in self._COMPLEX_HANDLER_PATTERNS)

                    # Determine confidence based on complexity
                    if is_async or has_complex_logic:
                        confidence = 0.92  # High priority - async/API handlers must be memoized
                        severity = Severity.HIGH
                    elif is_simple:
                        confidence = 0.55  # Low priority - simple setter
                        severity = Severity.LOW
                    else:
                        confidence = 0.75  # Medium priority - has body but not complex
                        severity = Severity.MEDIUM

                    findings.append(
                        self.create_finding(
                            title="Inline event handler without useCallback",
                            context=f"{prop_name}={{...}}",
                            file=file_path,
                            line_start=i,
                            description=(
                                f"Detected inline arrow function passed to `{prop_name}` prop. "
                                "This creates a new function reference on every render, "
                                "potentially causing unnecessary re-renders of child components."
                            ),
                            why_it_matters=(
                                "Inline event handlers cause:\n"
                                "- New function reference on every parent render\n"
                                "- Child components re-render unnecessarily\n"
                                "- Breaks shouldComponentUpdate / React.memo optimizations\n"
                                "- Can cause performance issues in lists with many items\n"
                                "- Makes dependency arrays unstable in useEffect"
                            ),
                            suggested_fix=(
                                "1. Wrap handlers with useCallback:\n"
                                "   const handleClick = useCallback(() => {\n"
                                "       doSomething(id);\n"
                                "   }, [id]);\n\n"
                                "2. Then pass the memoized handler:\n"
                                "   <Button onClick={handleClick} />\n\n"
                                "3. For simple handlers without dependencies:\n"
                                "   const handleClick = useCallback(() => {\n"
                                "       console.log('clicked');\n"
                                "   }, []);\n\n"
                                "4. If handler doesn't cause re-renders, this is lower priority"
                            ),
                            code_example=(
                                "// Before (new function every render)\n"
                                "function Parent({ items }) {\n"
                                "    return (\n"
                                "        <ul>\n"
                                "            {items.map(item => (\n"
                                "                <Item \n"
                                "                    key={item.id}\n"
                                "                    onClick={() => selectItem(item.id)} // New function!\n"
                                "                />\n"
                                "            ))}\n"
                                "        </ul>\n"
                                "    );\n"
                                "}\n\n"
                                "// After (stable reference)\n"
                                "function Parent({ items }) {\n"
                                "    const handleSelect = useCallback((id) => {\n"
                                "        selectItem(id);\n"
                                "    }, []);\n"
                                "    \n"
                                "    return (\n"
                                "        <ul>\n"
                                "            {items.map(item => (\n"
                                "                <Item \n"
                                "                    key={item.id}\n"
                                "                    onClick={() => handleSelect(item.id)}\n"
                                "                />\n"
                                "            ))}\n"
                                "        </ul>\n"
                                "    );\n"
                                "}\n\n"
                                "// Best: Use data attributes for lists\n"
                                "function Parent({ items }) {\n"
                                "    const handleClick = useCallback((e) => {\n"
                                "        const id = e.currentTarget.dataset.id;\n"
                                "        selectItem(id);\n"
                                "    }, []);\n"
                                "    \n"
                                "    return (\n"
                                "        <ul>\n"
                                "            {items.map(item => (\n"
                                "                <Item \n"
                                "                    key={item.id}\n"
                                "                    data-id={item.id}\n"
                                "                    onClick={handleClick} // Stable!\n"
                                "                />\n"
                                "            ))}\n"
                                "        </ul>\n"
                                "    );\n"
                                "}"
                            ),
                            confidence=confidence,
                            tags=["react", "performance", "usecallback", "memoization", "handlers"],
                        )
                    )
                    break  # Only one finding per line

        return findings
