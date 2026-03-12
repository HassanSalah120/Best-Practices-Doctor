"""
React useEffect Dependency Array Rule

Detects useEffect calls that omit the dependency array.
"""

from __future__ import annotations

from dataclasses import dataclass

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


@dataclass(frozen=True)
class _EffectCall:
    start: int
    line: int
    args: str


class UseEffectDependencyArrayRule(Rule):
    id = "react-useeffect-deps"
    name = "Missing useEffect Dependency Array"
    description = "Detects useEffect calls without a dependency array"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

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
        if "useEffect" not in (content or ""):
            return []

        findings: list[Finding] = []
        for call in self._find_use_effect_calls(content):
            if self._is_suppressed_by_exhaustive_deps_comment(content, call.line):
                continue

            args = self._split_top_level_args(call.args)
            if len(args) >= 2:
                continue

            findings.append(
                self.create_finding(
                    title="useEffect call without dependency array",
                    context="useeffect_missing_deps",
                    file=file_path,
                    line_start=call.line,
                    description=(
                        "Detected `useEffect` call without a dependency array. "
                        "This runs after every render and often creates stale closures "
                        "or unnecessary repeated effects."
                    ),
                    why_it_matters=(
                        "Missing dependencies are a common source of bugs in React apps: "
                        "race conditions, stale values, duplicate API calls, and performance regressions."
                    ),
                    suggested_fix=(
                        "Add an explicit dependency array and include all referenced values.\n"
                        "Prefer the `react-hooks/exhaustive-deps` ESLint rule to keep this correct over time."
                    ),
                    tags=["react", "hooks", "useeffect", "performance", "correctness"],
                    confidence=0.85,
                )
            )

        return findings

    def _find_use_effect_calls(self, content: str) -> list[_EffectCall]:
        out: list[_EffectCall] = []
        i = 0
        needle = "useEffect"
        n = len(content)

        while i < n:
            idx = content.find(needle, i)
            if idx < 0:
                break

            before = content[idx - 1] if idx > 0 else ""
            after_idx = idx + len(needle)
            after = content[after_idx] if after_idx < n else ""
            # Token boundary check so we don't match e.g. useEffectOnce.
            if (before.isalnum() or before == "_") or (after.isalnum() or after == "_"):
                i = idx + len(needle)
                continue

            j = after_idx
            while j < n and content[j].isspace():
                j += 1
            if j >= n or content[j] != "(":
                i = idx + len(needle)
                continue

            end = self._find_matching_paren(content, j)
            if end < 0:
                i = idx + len(needle)
                continue

            args = content[j + 1 : end]
            line = content.count("\n", 0, idx) + 1
            out.append(_EffectCall(start=idx, line=line, args=args))
            i = end + 1

        return out

    def _find_matching_paren(self, s: str, open_idx: int) -> int:
        depth = 0
        i = open_idx
        in_string: str | None = None
        in_line_comment = False
        in_block_comment = False

        while i < len(s):
            ch = s[i]
            nxt = s[i + 1] if i + 1 < len(s) else ""

            if in_line_comment:
                if ch == "\n":
                    in_line_comment = False
                i += 1
                continue
            if in_block_comment:
                if ch == "*" and nxt == "/":
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue
            if in_string:
                if ch == "\\":
                    i += 2
                    continue
                if ch == in_string:
                    in_string = None
                i += 1
                continue

            if ch == "/" and nxt == "/":
                in_line_comment = True
                i += 2
                continue
            if ch == "/" and nxt == "*":
                in_block_comment = True
                i += 2
                continue
            if ch in {"'", '"', "`"}:
                in_string = ch
                i += 1
                continue

            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return i
            i += 1

        return -1

    def _split_top_level_args(self, args_text: str) -> list[str]:
        args: list[str] = []
        cur: list[str] = []
        p_depth = b_depth = c_depth = 0
        in_string: str | None = None
        in_line_comment = False
        in_block_comment = False
        i = 0

        while i < len(args_text):
            ch = args_text[i]
            nxt = args_text[i + 1] if i + 1 < len(args_text) else ""

            if in_line_comment:
                cur.append(ch)
                if ch == "\n":
                    in_line_comment = False
                i += 1
                continue
            if in_block_comment:
                cur.append(ch)
                if ch == "*" and nxt == "/":
                    cur.append(nxt)
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue
            if in_string:
                cur.append(ch)
                if ch == "\\":
                    if nxt:
                        cur.append(nxt)
                        i += 2
                        continue
                elif ch == in_string:
                    in_string = None
                i += 1
                continue

            if ch == "/" and nxt == "/":
                cur.append(ch)
                cur.append(nxt)
                in_line_comment = True
                i += 2
                continue
            if ch == "/" and nxt == "*":
                cur.append(ch)
                cur.append(nxt)
                in_block_comment = True
                i += 2
                continue
            if ch in {"'", '"', "`"}:
                in_string = ch
                cur.append(ch)
                i += 1
                continue

            if ch == "(":
                p_depth += 1
            elif ch == ")":
                p_depth = max(0, p_depth - 1)
            elif ch == "[":
                b_depth += 1
            elif ch == "]":
                b_depth = max(0, b_depth - 1)
            elif ch == "{":
                c_depth += 1
            elif ch == "}":
                c_depth = max(0, c_depth - 1)

            if ch == "," and p_depth == 0 and b_depth == 0 and c_depth == 0:
                part = "".join(cur).strip()
                if part:
                    args.append(part)
                cur = []
                i += 1
                continue

            cur.append(ch)
            i += 1

        tail = "".join(cur).strip()
        if tail:
            args.append(tail)
        return args

    @staticmethod
    def _is_suppressed_by_exhaustive_deps_comment(content: str, line_no: int) -> bool:
        lines = content.splitlines()
        idx = max(0, line_no - 1)
        prev_lines = lines[max(0, idx - 2) : idx + 1]
        return any("react-hooks/exhaustive-deps" in ln for ln in prev_lines)
