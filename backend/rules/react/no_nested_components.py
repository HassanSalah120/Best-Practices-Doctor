"""
No Nested Components Rule

Detects React components defined inside other components.
"""
from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule

class NoNestedComponentsRule(Rule):
    id = "no-nested-components"
    name = "No Nested Components"
    description = "Detects components defined inside other components (causes remounts)"
    category = Category.PERFORMANCE
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _COMPONENT_DECL = re.compile(
        r"(?P<prefix>(?:^|\n)\s*)(?:export\s+)?(?:(?:function\s+(?P<func>[A-Z][A-Za-z0-9_]*)\s*\()|(?:const\s+(?P<const>[A-Z][A-Za-z0-9_]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z0-9_]+)\s*=>))",
        re.MULTILINE,
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
        findings = []
        matches = list(self._COMPONENT_DECL.finditer(content))

        found_nested = []
        for m in matches:
            name = m.group("func") or m.group("const")
            if not name:
                continue
            if self._brace_depth_at(content, m.start()) > 0:
                found_nested.append((name, m.start()))

        # Aggregate findings per file
        if not found_nested:
            return []

        # Dedup by name to avoid noise
        unique_names = sorted(list(set(n for n, _ in found_nested)))
        count = len(unique_names)
        
        lines = []
        for name, idx in found_nested:
            line = content.count("\n", 0, idx) + 1
            lines.append(line)
        
        first_line = lines[0]

        aggregated_finding = self.create_finding(
            title=f"Nested component definitions detected ({count} components)",
            context=f"file:{file_path}",
            file=file_path,
            line_start=first_line,
            description=(
                f"Detected {count} component(s) defined inside another component: {', '.join(unique_names)}.\n"
                "Defining components inside others causes them to be re-created on every render, "
                "leading to performance issues and loss of focus/state."
            ),
            why_it_matters=(
                "When a child component is defined inside a parent, it is a *new* component type on every render. "
                "React will unmount and remount it completely, destroying its state and DOM focus."
            ),
            suggested_fix=(
                "Move the nested component definition to the top level of the file, "
                "outside the parent component."
            ),
            tags=["react", "performance", "rendering"],
            confidence=0.85,
            evidence_signals=[f"count={count}", f"names={','.join(unique_names)}"]
        )
        
        for name, idx in found_nested:
             line = content.count("\n", 0, idx) + 1
             aggregated_finding.evidence_signals.append(f"nested_at_line={line}: {name}")

        return [aggregated_finding]

    @staticmethod
    def _brace_depth_at(content: str, stop_idx: int) -> int:
        depth = 0
        in_single = False
        in_double = False
        in_template = False
        in_line_comment = False
        in_block_comment = False
        escape = False
        i = 0

        while i < stop_idx:
            ch = content[i]
            nxt = content[i + 1] if i + 1 < stop_idx else ""

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

            if in_single:
                if not escape and ch == "'":
                    in_single = False
                escape = (ch == "\\") and not escape
                i += 1
                continue

            if in_double:
                if not escape and ch == '"':
                    in_double = False
                escape = (ch == "\\") and not escape
                i += 1
                continue

            if in_template:
                if not escape and ch == "`":
                    in_template = False
                escape = (ch == "\\") and not escape
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
            if ch == "'":
                in_single = True
                escape = False
                i += 1
                continue
            if ch == '"':
                in_double = True
                escape = False
                i += 1
                continue
            if ch == "`":
                in_template = True
                escape = False
                i += 1
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth = max(0, depth - 1)
            i += 1

        return depth
