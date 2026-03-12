"""
UseEffect Cleanup Missing Rule

Detects useEffect hooks with side effects that need cleanup but don't have it.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class UseEffectCleanupMissingRule(Rule):
    id = "useeffect-cleanup-missing"
    name = "UseEffect Cleanup Missing"
    description = "Detects useEffect with side effects that need cleanup but don't have it"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Patterns that indicate side effects needing cleanup
    _SIDE_EFFECT_PATTERNS = [
        # Subscriptions
        re.compile(r"\.subscribe\s*\(", re.IGNORECASE),
        re.compile(r"addEventListener\s*\(", re.IGNORECASE),
        re.compile(r"on\s*\(['\"]", re.IGNORECASE),  # socket.on, emitter.on
        # Timers
        re.compile(r"setInterval\s*\(", re.IGNORECASE),
        re.compile(r"setTimeout\s*\(", re.IGNORECASE),
        re.compile(r"requestAnimationFrame\s*\(", re.IGNORECASE),
        re.compile(r"requestIdleCallback\s*\(", re.IGNORECASE),
        # WebSocket
        re.compile(r"new\s+WebSocket\s*\(", re.IGNORECASE),
        re.compile(r"socket\.connect\s*\(", re.IGNORECASE),
        # Fetch (covered by separate rule, but included for completeness)
        re.compile(r"fetch\s*\(", re.IGNORECASE),
        # Event sources
        re.compile(r"new\s+EventSource\s*\(", re.IGNORECASE),
        # External libraries
        re.compile(r"\.on\s*\(", re.IGNORECASE),  # jQuery, socket.io, etc.
        re.compile(r"\.bind\s*\(", re.IGNORECASE),  # jQuery
    ]

    # Patterns that indicate cleanup is present
    _CLEANUP_PATTERNS = [
        re.compile(r"return\s*\(\s*\)\s*=>", re.IGNORECASE),  # return () => ...
        re.compile(r"return\s*\(\s*\)\s*=>\s*\{", re.IGNORECASE),
        re.compile(r"return\s*function\s*\(\s*\)\s*\{", re.IGNORECASE),
        re.compile(r"return\s*\(\s*\)\s*=>\s*clear", re.IGNORECASE),  # clearTimeout/clearInterval
        re.compile(r"return\s*\(\s*\)\s*=>\s*\{", re.IGNORECASE),
        re.compile(r"\.removeEventListener\s*\(", re.IGNORECASE),
        re.compile(r"\.unsubscribe\s*\(\)", re.IGNORECASE),
        re.compile(r"\.off\s*\(", re.IGNORECASE),  # socket.off, emitter.off
        re.compile(r"\.disconnect\s*\(\)", re.IGNORECASE),
        re.compile(r"clearTimeout\s*\(", re.IGNORECASE),
        re.compile(r"clearInterval\s*\(", re.IGNORECASE),
        re.compile(r"cancelAnimationFrame\s*\(", re.IGNORECASE),
        re.compile(r"abortController", re.IGNORECASE),
        re.compile(r"abort\s*\(\)", re.IGNORECASE),
        re.compile(r"isMounted\s*=\s*false", re.IGNORECASE),
        re.compile(r"isSubscribed\s*=\s*false", re.IGNORECASE),
        re.compile(r"cancelled\s*=\s*true", re.IGNORECASE),
        re.compile(r"canceled\s*=\s*true", re.IGNORECASE),
        re.compile(r"ignore\s*=\s*true", re.IGNORECASE),
    ]

    _USE_EFFECT_PATTERN = re.compile(r"useEffect\s*\(\s*\(", re.IGNORECASE)

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

        # Find all useEffect blocks
        for match in self._USE_EFFECT_PATTERN.finditer(text):
            # Extract the useEffect body (approximate)
            start = match.start()
            
            # Look for the effect body - find the closing of the first function
            window = text[start: start + 2500]  # Reasonable window size
            
            # Check for side effects in this useEffect
            detected_effects = []
            for pattern in self._SIDE_EFFECT_PATTERNS:
                if pattern.search(window):
                    # Extract which effect was detected
                    effect_name = self._get_effect_name(pattern)
                    if effect_name and effect_name not in detected_effects:
                        detected_effects.append(effect_name)

            if not detected_effects:
                continue

            # Check for cleanup patterns
            has_cleanup = any(pattern.search(window) for pattern in self._CLEANUP_PATTERNS)

            if has_cleanup:
                continue

            # Calculate line number
            line = text.count("\n", 0, start) + 1

            findings.append(
                self.create_finding(
                    title="useEffect missing cleanup for side effects",
                    context=f"Detected: {', '.join(detected_effects)}",
                    file=file_path,
                    line_start=line,
                    description=(
                        f"Detected side effects in useEffect that need cleanup: {', '.join(detected_effects)}. "
                        "Without cleanup, these can cause memory leaks and race conditions."
                    ),
                    why_it_matters=(
                        "Missing cleanup in useEffect causes:\n"
                        "- Memory leaks when components unmount\n"
                        "- Race conditions when dependencies change\n"
                        "- State updates on unmounted components (React warnings)\n"
                        "- Unnecessary network requests\n"
                        "- Event listeners firing after component destruction"
                    ),
                    suggested_fix=(
                        "1. Return a cleanup function from useEffect:\n"
                        "   useEffect(() => {\n"
                        "       const timer = setInterval(callback, 1000);\n"
                        "       return () => clearInterval(timer);\n"
                        "   }, []);\n\n"
                        "2. For subscriptions:\n"
                        "   useEffect(() => {\n"
                        "       const sub = observable.subscribe(callback);\n"
                        "       return () => sub.unsubscribe();\n"
                        "   }, []);\n\n"
                        "3. For event listeners:\n"
                        "   useEffect(() => {\n"
                        "       const handler = (e) => {};\n"
                        "       window.addEventListener('resize', handler);\n"
                        "       return () => window.removeEventListener('resize', handler);\n"
                        "   }, []);"
                    ),
                    code_example=(
                        "// Before (memory leak)\n"
                        "useEffect(() => {\n"
                        "    setInterval(() => setCount(c => c + 1), 1000);\n"
                        "}, []);\n\n"
                        "// After (proper cleanup)\n"
                        "useEffect(() => {\n"
                        "    const timer = setInterval(() => setCount(c => c + 1), 1000);\n"
                        "    return () => clearInterval(timer);\n"
                        "}, []);\n\n"
                        "// For async operations\n"
                        "useEffect(() => {\n"
                        "    let ignore = false;\n"
                        "    fetchData().then(data => {\n"
                        "        if (!ignore) setState(data);\n"
                        "    });\n"
                        "    return () => { ignore = true; };\n"
                        "}, []);"
                    ),
                    confidence=0.85,
                    tags=["react", "useeffect", "cleanup", "memory-leak", "hooks"],
                )
            )

        return findings

    def _get_effect_name(self, pattern: re.Pattern) -> str | None:
        """Get a human-readable name for the detected effect."""
        pattern_str = pattern.pattern
        if "subscribe" in pattern_str:
            return "subscription"
        elif "addEventListener" in pattern_str:
            return "event listener"
        elif "setInterval" in pattern_str:
            return "setInterval"
        elif "setTimeout" in pattern_str:
            return "setTimeout"
        elif "requestAnimationFrame" in pattern_str:
            return "requestAnimationFrame"
        elif "WebSocket" in pattern_str:
            return "WebSocket"
        elif "EventSource" in pattern_str:
            return "EventSource"
        elif "fetch" in pattern_str:
            return "fetch"
        elif ".on(" in pattern_str:
            return "event emitter"
        else:
            return None
