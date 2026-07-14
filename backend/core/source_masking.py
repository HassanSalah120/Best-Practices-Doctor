"""Small lexical helpers shared by regex-backed rules.

The helpers preserve offsets and newlines so findings can still report the
original source location while avoiding matches inside comments or strings.
They are intentionally conservative and do not attempt to replace a parser.
"""

from __future__ import annotations


def mask_comments_and_strings(source: str, *, hash_comments: bool = False) -> str:
    """Replace comment/string contents with spaces while preserving layout."""

    text = source or ""
    out = list(text)
    i = 0
    state = "code"
    quote = ""

    def mask(position: int) -> None:
        if out[position] not in {"\n", "\r"}:
            out[position] = " "

    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if state == "line_comment":
            if ch in {"\n", "\r"}:
                state = "code"
            else:
                mask(i)
            i += 1
            continue

        if state == "block_comment":
            mask(i)
            if ch == "*" and nxt == "/":
                mask(i + 1)
                i += 2
                state = "code"
            else:
                i += 1
            continue

        if state == "string":
            mask(i)
            if ch == "\\":
                if i + 1 < len(text):
                    mask(i + 1)
                i += 2
                continue
            if ch == quote:
                state = "code"
            i += 1
            continue

        if ch == "/" and nxt == "/":
            mask(i)
            mask(i + 1)
            i += 2
            state = "line_comment"
            continue
        if ch == "/" and nxt == "*":
            mask(i)
            mask(i + 1)
            i += 2
            state = "block_comment"
            continue
        if hash_comments and ch == "#":
            mask(i)
            i += 1
            state = "line_comment"
            continue
        if ch in {"'", '"', "`"}:
            quote = ch
            mask(i)
            i += 1
            state = "string"
            continue
        i += 1

    return "".join(out)


def mask_comments(source: str, *, hash_comments: bool = False) -> str:
    """Mask comments but retain string literals and exact source offsets."""

    text = source or ""
    out = list(text)
    i = 0
    state = "code"
    quote = ""

    def mask(position: int) -> None:
        if out[position] not in {"\n", "\r"}:
            out[position] = " "

    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if state == "line_comment":
            if ch in {"\n", "\r"}:
                state = "code"
            else:
                mask(i)
            i += 1
            continue
        if state == "block_comment":
            mask(i)
            if ch == "*" and nxt == "/":
                mask(i + 1)
                i += 2
                state = "code"
            else:
                i += 1
            continue
        if state == "string":
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                state = "code"
            i += 1
            continue
        if ch == "/" and nxt == "/":
            mask(i)
            mask(i + 1)
            i += 2
            state = "line_comment"
            continue
        if ch == "/" and nxt == "*":
            mask(i)
            mask(i + 1)
            i += 2
            state = "block_comment"
            continue
        if hash_comments and ch == "#":
            mask(i)
            i += 1
            state = "line_comment"
            continue
        if ch in {"'", '"', "`"}:
            quote = ch
            state = "string"
        i += 1
    return "".join(out)
