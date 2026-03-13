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

    # Trivial handlers that DON'T need useCallback (skip these)
    _TRIVIAL_HANDLER_PATTERNS = [
        # Simple boolean toggle: onClick={() => setIsOpen(!isOpen)} or onClick={() => setOpen(!open)}
        re.compile(r"set[A-Z][a-zA-Z]*\s*\(\s*![a-zA-Z_][a-zA-Z0-9_]*\s*\)", re.IGNORECASE),
        # Simple setter with literal: onClick={() => setActive(true)}
        re.compile(r"set[A-Z][a-zA-Z]*\s*\(\s*(?:true|false|null|undefined|\d+|\"[^\"]*\")\s*\)", re.IGNORECASE),
        # Simple setter with variable: onClick={() => setValue(value)}
        re.compile(r"set[A-Z][a-zA-Z]*\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)", re.IGNORECASE),
        # Simple navigation: onClick={() => navigate('/path')}
        re.compile(r"navigate\s*\(\s*[\"'][^\"']*[\"']\s*\)", re.IGNORECASE),
        # Simple router.visit: onClick={() => router.visit('/path')}
        re.compile(r"router\.(visit|get|post|put|delete|patch)\s*\(\s*[\"'][^\"']*[\"']\s*\)", re.IGNORECASE),
        # Simple Inertia navigation: onClick={() => router.push('/path')}
        re.compile(r"router\.(push|replace)\s*\(\s*[\"'][^\"']*[\"']\s*\)", re.IGNORECASE),
        # Simple window.location: onClick={() => window.location.href = '/path'}
        re.compile(r"window\.location\.(href|assign|replace)\s*=\s*[\"'][^\"']*[\"']", re.IGNORECASE),
        # Simple console.log only
        re.compile(r"console\.(log|warn|error)\s*\([^)]*\)\s*\}?\s*\)", re.IGNORECASE),
        # Simple close/dismiss handlers
        re.compile(r"onClose\s*=\s*\{\s*\(\)\s*=>\s*\w+\s*\}", re.IGNORECASE),
        # Simple preventDefault only
        re.compile(r"e\.preventDefault\s*\(\s*\)\s*\}", re.IGNORECASE),
        # Simple form submit: onSubmit={() => post('/path')}
        re.compile(r"(post|put|patch|delete)\s*\(\s*[\"'][^\"']*[\"']\s*\)\s*\}", re.IGNORECASE),
        # Simple toggle with function call: onClick={() => toggle()}
        re.compile(r"toggle[A-Z][a-zA-Z]*\s*\(\s*\)\s*\}", re.IGNORECASE),
        # Simple ref access: onClick={() => inputRef.current?.focus()}
        re.compile(r"[a-zA-Z_]+Ref\.current\s*\??\.\s*[a-zA-Z]+\s*\(\s*\)\s*\}", re.IGNORECASE),
        # Form submission with preventDefault: onSubmit={(e) => { e.preventDefault(); post(); }}
        re.compile(r"e\.preventDefault\s*\(\s*\)[;\s]*(?:post|put|patch|delete|submit|handleSubmit)", re.IGNORECASE),
        # Simple setter with prev value: onClick={() => setX(prev => !prev)}
        re.compile(r"set[A-Z][a-zA-Z]*\s*\(\s*(?:prev|previous)\s*=>", re.IGNORECASE),
        # Inline void call: onClick={() => void action()}
        re.compile(r"void\s+[a-zA-Z_]+\s*\(", re.IGNORECASE),
        # Simple event passthrough: onClick={() => handleClick()}
        re.compile(r"handle[A-Z][a-zA-Z]*\s*\(\s*\)\s*\}", re.IGNORECASE),
        # Inline increment/decrement: onClick={() => setCount(c => c + 1)}
        re.compile(r"set[A-Z][a-zA-Z]*\s*\(\s*\w+\s*=>\s*\w+\s*[-+]\s*1\s*\)", re.IGNORECASE),
    ]
    
    # Files that should be excluded (not React components)
    _NON_COMPONENT_FILES = [
        re.compile(r"\.utils?\.tsx?$", re.IGNORECASE),
        re.compile(r"\.helpers?\.tsx?$", re.IGNORECASE),
        re.compile(r"/utils?/", re.IGNORECASE),
        re.compile(r"/helpers?/", re.IGNORECASE),
        re.compile(r"/hooks/", re.IGNORECASE),
        re.compile(r"/types/", re.IGNORECASE),
        re.compile(r"\.types\.tsx?$", re.IGNORECASE),
        re.compile(r"/constants?/", re.IGNORECASE),
        re.compile(r"/config/", re.IGNORECASE),
        re.compile(r"/i18n/", re.IGNORECASE),
        re.compile(r"/services?/", re.IGNORECASE),
        re.compile(r"/api/", re.IGNORECASE),
    ]

    # Context patterns where handlers DO need memoization (higher priority)
    _NEEDS_MEMOIZATION_CONTEXT = [
        re.compile(r"\.map\s*\([^)]*\)\s*=>", re.IGNORECASE),  # Inside a map/list
    ]
    _MEMOIZED_CHILD_CONTEXT = [
        re.compile(r"React\.memo", re.IGNORECASE),  # Passed to memoized component
        re.compile(r"memo\s*\(", re.IGNORECASE),  # Memoized component nearby
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

    # Native DOM element patterns - handlers on these don't benefit from useCallback
    # because there's no child component to re-render
    _NATIVE_ELEMENT_PATTERNS = [
        re.compile(r"<button\b", re.IGNORECASE),
        re.compile(r"<a\s", re.IGNORECASE),
        re.compile(r"<input\b", re.IGNORECASE),
        re.compile(r"<select\b", re.IGNORECASE),
        re.compile(r"<textarea\b", re.IGNORECASE),
        re.compile(r"<form\b", re.IGNORECASE),
    ]

    _ALLOWLIST_PATHS = (
        "/tests/",
        "/test/",
        "/__tests__/",
        "/node_modules/",
    )
    _JSX_TAG_PATTERN = re.compile(r"<\s*(?P<tag>[A-Za-z][A-Za-z0-9_.:-]*)")

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

        # Skip non-component files (utility files, hooks, types, etc.)
        if any(p.search(norm_path) for p in self._NON_COMPONENT_FILES):
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

                    is_trivial = any(p.search(line) for p in self._TRIVIAL_HANDLER_PATTERNS)

                    # Check if this is a simple handler (no body) - lower severity
                    is_simple = "=>" in line and "{" not in line.split("=>")[1].split(",")[0]

                    # Check for async or complex patterns - HIGHER severity
                    is_async = bool(self._ASYNC_HANDLER_PATTERN.search(line))
                    has_complex_logic = any(p.search(line) for p in self._COMPLEX_HANDLER_PATTERNS)

                    context_window = text[max(0, text.find(line)-150):text.find(line)+150]
                    is_in_list_context = any(p.search(context_window) for p in self._NEEDS_MEMOIZATION_CONTEXT)

                    # Distinguish native elements from custom components. Native handlers are still
                    # worth reporting, but at lower confidence because the performance payoff is smaller.
                    is_native_element = any(p.search(line) for p in self._NATIVE_ELEMENT_PATTERNS)
                    tag_match = self._JSX_TAG_PATTERN.search(line)
                    tag_name = (tag_match.group("tag") if tag_match else "").strip()
                    is_custom_component = bool(tag_name and tag_name[:1].isupper())
                    has_memoized_child_context = any(p.search(context_window) for p in self._MEMOIZED_CHILD_CONTEXT)
                    if is_custom_component and tag_name:
                        has_memoized_child_context = has_memoized_child_context or self._is_memoized_component_in_file(
                            tag_name,
                            text,
                        )

                    # Native DOM handlers are usually fine without useCallback. Keep the rule
                    # focused on custom component props or genuinely memoization-sensitive cases.
                    if is_native_element and not is_custom_component:
                        break

                    if not (is_custom_component and has_memoized_child_context):
                        break

                    if is_trivial and not (is_async or has_complex_logic):
                        break

                    # Determine confidence based on complexity and element type
                    if is_async or has_complex_logic:
                        confidence = 0.92  # High priority - async/API handlers must be memoized
                        severity = Severity.HIGH
                    elif has_memoized_child_context and is_in_list_context:
                        confidence = 0.88
                        severity = Severity.MEDIUM
                    elif is_simple or is_trivial:
                        confidence = 0.60
                        severity = Severity.LOW
                    else:
                        confidence = 0.70  # Medium priority - has body but not complex
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

    @staticmethod
    def _is_memoized_component_in_file(component_name: str, text: str) -> bool:
        escaped = re.escape(component_name)
        patterns = [
            re.compile(rf"\bconst\s+{escaped}\s*=\s*memo\s*\(", re.IGNORECASE),
            re.compile(rf"\bconst\s+{escaped}\s*=\s*React\.memo\s*\(", re.IGNORECASE),
            re.compile(rf"\bmemo\s*\(\s*function\s+{escaped}\b", re.IGNORECASE),
            re.compile(rf"\bReact\.memo\s*\(\s*function\s+{escaped}\b", re.IGNORECASE),
            re.compile(rf"\bexport\s+default\s+memo\s*\(\s*function\s+{escaped}\b", re.IGNORECASE),
            re.compile(rf"\bexport\s+default\s+React\.memo\s*\(\s*function\s+{escaped}\b", re.IGNORECASE),
        ]
        return any(pattern.search(text) for pattern in patterns)
