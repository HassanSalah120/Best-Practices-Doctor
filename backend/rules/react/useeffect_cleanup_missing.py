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
        # Fetch is optional (configured via threshold include_fetch_effects)
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
        re.compile(r"return\s+[a-zA-Z_][a-zA-Z0-9_]*\s*;", re.IGNORECASE),  # return cleanup;
    ]

    _USE_EFFECT_PATTERN = re.compile(r"\buseEffect\s*\(", re.IGNORECASE)

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

        include_fetch_effects = bool(self.get_threshold("include_fetch_effects", False))
        min_side_effect_signals = max(1, int(self.get_threshold("min_side_effect_signals", 1)))
        text = content or ""

        # Find all useEffect blocks
        for start, window in self._iter_useeffect_blocks(text):

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
            if not include_fetch_effects:
                detected_effects = [effect for effect in detected_effects if effect != "fetch"]
            if len(detected_effects) < min_side_effect_signals:
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
                    evidence_signals=[
                        f"detected_effects={','.join(detected_effects)}",
                        f"include_fetch_effects={int(include_fetch_effects)}",
                        f"min_side_effect_signals={min_side_effect_signals}",
                    ],
                    metadata={
                        "decision_profile": {
                            "detected_effects": detected_effects,
                            "include_fetch_effects": include_fetch_effects,
                            "min_side_effect_signals": min_side_effect_signals,
                            "has_cleanup": has_cleanup,
                        }
                    },
                )
            )

        return findings

    def _iter_useeffect_blocks(self, text: str) -> list[tuple[int, str]]:
        blocks: list[tuple[int, str]] = []
        for match in self._USE_EFFECT_PATTERN.finditer(text):
            paren_start = text.find("(", match.start())
            if paren_start == -1:
                continue
            paren_end = self._find_matching_paren(text, paren_start)
            if paren_end == -1:
                window = text[match.start(): match.start() + 4000]
            else:
                window = text[match.start(): paren_end + 1]
            blocks.append((match.start(), window))
        return blocks

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
