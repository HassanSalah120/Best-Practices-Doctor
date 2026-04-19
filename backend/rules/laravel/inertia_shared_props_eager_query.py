"""
Inertia Shared Props Eager Query Rule

Detects database queries executed eagerly in global Inertia shared props.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class InertiaSharedPropsEagerQueryRule(Rule):
    id = "inertia-shared-props-eager-query"
    name = "Inertia Shared Props Eager Query"
    description = "Detects eager database queries inside global Inertia shared props"
    category = Category.PERFORMANCE
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types = ["laravel_inertia_react", "laravel_inertia_vue"]
    regex_file_extensions = [".php"]

    _PATH_HINTS = ("handleinertiarequests.php", "/middleware/", "/providers/")
    _FILE_HINTS = ("inertia::share", "function share(", "parent::share(")
    _QUERY_TOKENS = (
        "::all(",
        "::count(",
        "::latest(",
        "::oldest(",
        "::paginate(",
        "::simplepaginate(",
        "::cursorpaginate(",
        "::query()->count(",
        "::query()->get(",
        "::query()->first(",
        "::query()->paginate(",
        "db::table(",
        "db::query(",
        "db::select(",
    )
    _CACHE_TOKENS = (
        "cache::remember(",
        "cache::rememberforever(",
        "cache()->remember(",
        "cache()->rememberforever(",
        "->remember(",
        "->rememberforever(",
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
        norm = (file_path or "").replace("\\", "/").lower()
        text = content or ""
        low = text.lower()
        require_inertia_context = bool(self.get_threshold("require_inertia_context", True))
        require_global_share_context = bool(self.get_threshold("require_global_share_context", True))
        allow_lazy_or_cached = bool(self.get_threshold("allow_lazy_or_cached", True))
        min_signal_count = int(self.get_threshold("min_signal_count", 1) or 1)
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)

        inertia_context, global_share_context, context_signals = self._detect_context(norm, low)
        if require_inertia_context and not inertia_context:
            return []
        if require_global_share_context and not global_share_context:
            return []
        if len(context_signals) < min_signal_count:
            return []

        lines = text.splitlines()
        share_ranges = self._collect_share_ranges(lines)
        helper_query_methods = self._collect_helper_methods_with_queries(lines)

        for line_no, line in enumerate(lines, start=1):
            if share_ranges and not self._line_in_ranges(line_no, share_ranges):
                continue
            line_low = line.lower()
            if "=>" not in line_low:
                continue
            if allow_lazy_or_cached and ("fn" in line_low or "function" in line_low):
                continue
            if allow_lazy_or_cached and any(token in line_low for token in self._CACHE_TOKENS):
                continue
            query_token = next((token for token in self._QUERY_TOKENS if token in line_low), "")
            delegated_method = ""
            if not query_token:
                delegated_method = self._extract_delegated_method_name(line_low)
                if delegated_method and delegated_method in helper_query_methods:
                    query_token = f"delegated:{delegated_method}"
            if not query_token:
                continue
            confidence = 0.84 if "::count(" in query_token or "::all(" in query_token else 0.8
            if delegated_method:
                confidence = max(confidence, 0.86)
            if not global_share_context:
                confidence -= 0.12
            if confidence + 1e-9 < min_confidence:
                continue
            evidence = list(context_signals)
            evidence.extend(
                [
                    "shared_props_eager_query=true",
                    f"query_token={query_token}",
                    f"line={line_no}",
                ]
            )
            if delegated_method:
                evidence.append(f"delegated_method={delegated_method}")
                evidence.append("delegated_method_contains_query=true")
            return [
                self.create_finding(
                    title="Inertia shared props run an eager query on every request",
                    context=f"{file_path}:{line_no}:share",
                    file=file_path,
                    line_start=line_no,
                    description=(
                        "Detected a database query executed directly in global Inertia shared props instead of "
                        "behind a lazy closure."
                    ),
                    why_it_matters=(
                        "Global shared props run on every Inertia response. Eager queries there add hidden latency "
                        "and can degrade the entire app."
                    ),
                    suggested_fix=(
                        "Wrap expensive shared props in lazy closures such as `fn () => Order::count()` and avoid "
                        "sharing large query results globally when the page does not always need them."
                    ),
                    tags=["laravel", "inertia", "performance", "shared-props"],
                    confidence=confidence,
                    evidence_signals=evidence,
                )
            ]
        return []

    def _detect_context(self, norm_path: str, content_lower: str) -> tuple[bool, bool, list[str]]:
        signals: list[str] = []
        inertia_context = False
        global_share_context = False

        if any(hint in norm_path for hint in self._PATH_HINTS):
            inertia_context = True
            signals.append("inertia_context=path_hint")
        if "inertia::share" in content_lower:
            inertia_context = True
            global_share_context = True
            signals.append("inertia_context=inertia_share_call")
        if "function share(" in content_lower or "parent::share(" in content_lower:
            inertia_context = True
            global_share_context = True
            signals.append("global_share_context=share_method")
        if not global_share_context and any(hint in content_lower for hint in self._FILE_HINTS):
            global_share_context = True
            signals.append("global_share_context=file_hint")

        return inertia_context, global_share_context, signals

    def _collect_share_ranges(self, lines: list[str]) -> list[tuple[int, int]]:
        ranges: list[tuple[int, int]] = []
        for idx, line in enumerate(lines, start=1):
            if re.search(r"\bfunction\s+share\s*\(", line, flags=re.IGNORECASE):
                end = self._find_block_end_by_braces(lines, idx)
                ranges.append((idx, end))
            if "inertia::share(" in line.lower():
                end = self._find_call_end_by_parenthesis(lines, idx)
                ranges.append((idx, end))
        return ranges

    def _collect_helper_methods_with_queries(self, lines: list[str]) -> set[str]:
        methods: set[str] = set()
        pattern = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", flags=re.IGNORECASE)
        for idx, line in enumerate(lines, start=1):
            match = pattern.search(line)
            if not match:
                continue
            method_name = str(match.group(1) or "").lower()
            if not method_name:
                continue
            end = self._find_block_end_by_braces(lines, idx)
            body = "\n".join(lines[idx - 1 : end]).lower()
            if any(token in body for token in self._QUERY_TOKENS):
                methods.add(method_name)
        return methods

    def _extract_delegated_method_name(self, line_lower: str) -> str:
        match = re.search(r"=>\s*\$this(?:->|\?->)([a-z_][a-z0-9_]*)\s*\(", line_lower)
        if not match:
            return ""
        return str(match.group(1) or "").lower().strip()

    def _line_in_ranges(self, line_no: int, ranges: list[tuple[int, int]]) -> bool:
        for start, end in ranges:
            if start <= line_no <= end:
                return True
        return False

    def _find_block_end_by_braces(self, lines: list[str], start_line: int) -> int:
        depth = 0
        seen_open = False
        for idx in range(start_line - 1, len(lines)):
            line = lines[idx]
            for char in line:
                if char == "{":
                    depth += 1
                    seen_open = True
                elif char == "}":
                    if seen_open:
                        depth -= 1
                        if depth <= 0:
                            return idx + 1
        return len(lines)

    def _find_call_end_by_parenthesis(self, lines: list[str], start_line: int) -> int:
        depth = 0
        seen_open = False
        for idx in range(start_line - 1, len(lines)):
            line = lines[idx]
            start_col = 0
            if idx == start_line - 1:
                marker = line.lower().find("inertia::share(")
                if marker >= 0:
                    start_col = marker + len("inertia::share")
            for char in line[start_col:]:
                if char == "(":
                    depth += 1
                    seen_open = True
                elif char == ")":
                    if seen_open:
                        depth -= 1
                        if depth <= 0:
                            return idx + 1
        return len(lines)
