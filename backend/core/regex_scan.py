"""
Regex scanning utilities for lightweight lint rules.

These helpers are intentionally simple and fast. They operate on file content and return
line-level matches so rules can create stable findings without parsing AST.
"""

from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class RegexHit:
    line_number: int
    line: str
    match: str


def regex_scan(content: str, patterns: list[re.Pattern[str]]) -> list[RegexHit]:
    """
    Scan content with the given compiled regex patterns and return line-level hits.

    Notes:
    - Patterns should be compiled with appropriate flags (typically re.IGNORECASE).
    - This function is line-oriented for predictable locations in findings.
    """
    hits: list[RegexHit] = []
    if not content or not patterns:
        return hits

    lines = content.splitlines()
    for i, line in enumerate(lines, start=1):
        for pat in patterns:
            m = pat.search(line)
            if not m:
                continue
            hits.append(RegexHit(line_number=i, line=line.rstrip("\n")[:240], match=m.group(0)[:120]))
    return hits

