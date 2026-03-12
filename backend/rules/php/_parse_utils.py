"""
Small parsing helpers for security heuristics.

We intentionally keep these lightweight and best-effort:
- extract parenthesis content for a call expression
- split arguments on top-level commas (ignoring strings and nested structures)
"""

from __future__ import annotations


def extract_paren_content(expr: str, open_paren_index: int) -> str | None:
    """Return content inside matching parentheses starting at `open_paren_index` (which must be '(')."""
    if not expr:
        return None
    if open_paren_index < 0 or open_paren_index >= len(expr):
        return None
    if expr[open_paren_index] != "(":
        return None

    depth = 0
    in_single = False
    in_double = False
    escape = False
    start = open_paren_index + 1

    for i in range(open_paren_index, len(expr)):
        ch = expr[i]
        if i == open_paren_index:
            depth = 1
            continue

        if escape:
            escape = False
            continue

        if in_single:
            if ch == "\\":
                escape = True
            elif ch == "'":
                in_single = False
            continue

        if in_double:
            if ch == "\\":
                escape = True
            elif ch == '"':
                in_double = False
            continue

        if ch == "'":
            in_single = True
            continue
        if ch == '"':
            in_double = True
            continue

        if ch == "(":
            depth += 1
            continue
        if ch == ")":
            depth -= 1
            if depth == 0:
                return expr[start:i]
            continue

    return None


def split_top_level_args(arg_src: str) -> list[str]:
    """Split a call argument string into top-level args (best-effort)."""
    if arg_src is None:
        return []

    parts: list[str] = []
    cur: list[str] = []

    p_depth = 0
    b_depth = 0
    c_depth = 0

    in_single = False
    in_double = False
    escape = False

    for ch in str(arg_src):
        if escape:
            cur.append(ch)
            escape = False
            continue

        if in_single:
            cur.append(ch)
            if ch == "\\":
                escape = True
            elif ch == "'":
                in_single = False
            continue

        if in_double:
            cur.append(ch)
            if ch == "\\":
                escape = True
            elif ch == '"':
                in_double = False
            continue

        if ch == "'":
            in_single = True
            cur.append(ch)
            continue
        if ch == '"':
            in_double = True
            cur.append(ch)
            continue

        if ch == "(":
            p_depth += 1
            cur.append(ch)
            continue
        if ch == ")":
            p_depth = max(0, p_depth - 1)
            cur.append(ch)
            continue
        if ch == "[":
            b_depth += 1
            cur.append(ch)
            continue
        if ch == "]":
            b_depth = max(0, b_depth - 1)
            cur.append(ch)
            continue
        if ch == "{":
            c_depth += 1
            cur.append(ch)
            continue
        if ch == "}":
            c_depth = max(0, c_depth - 1)
            cur.append(ch)
            continue

        if ch == "," and p_depth == 0 and b_depth == 0 and c_depth == 0:
            part = "".join(cur).strip()
            if part:
                parts.append(part)
            cur = []
            continue

        cur.append(ch)

    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)

    return parts


def is_simple_string_literal(expr: str) -> bool:
    s = (expr or "").strip()
    if len(s) < 2:
        return False
    if (s[0] == s[-1] == "'") or (s[0] == s[-1] == '"'):
        return True
    return False


def string_literal_is_interpolated(expr: str) -> bool:
    """True if expr is a double-quoted string literal that contains '$'."""
    s = (expr or "").strip()
    if len(s) < 2:
        return False
    if s[0] == '"' and s[-1] == '"':
        return "$" in s
    return False

