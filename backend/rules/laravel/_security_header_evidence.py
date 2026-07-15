"""Shared, path-independent evidence helpers for browser security-header rules."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from schemas.facts import Facts


SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)

_HEADER_WRITE = re.compile(
    r"(?:"
    r"headers?\s*->\s*(?:set|add|replace)\s*\("
    r"|->\s*(?:header|withheaders)\s*\("
    r"|\bheader\s*\("
    r"|\badd_header\b"
    r"|\bheader\s+(?:always\s+)?set\b"
    r")",
    re.IGNORECASE,
)
_CSP_PACKAGE = re.compile(
    r"(?:spatie\\csp|addcspheaders|contentsecuritypolicy(?:middleware|header|serviceprovider)?)",
    re.IGNORECASE,
)
_TEXT_SUFFIXES = {
    ".php",
    ".conf",
    ".config",
    ".htaccess",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
}


def normalize_path(path: str) -> str:
    return str(path or "").replace("\\", "/").lower()


def strip_comments(text: str) -> str:
    """Remove PHP/JS-style comments while preserving strings and line positions."""
    source = text or ""
    out = list(source)
    state = "code"
    quote = ""
    index = 0
    while index < len(source):
        char = source[index]
        nxt = source[index + 1] if index + 1 < len(source) else ""

        if state == "string":
            if char == "\\":
                index += 2
                continue
            if char == quote:
                state = "code"
            index += 1
            continue

        if state == "line_comment":
            if char in "\r\n":
                state = "code"
            else:
                out[index] = " "
            index += 1
            continue

        if state == "block_comment":
            if char == "*" and nxt == "/":
                out[index] = out[index + 1] = " "
                state = "code"
                index += 2
                continue
            if char not in "\r\n":
                out[index] = " "
            index += 1
            continue

        if char in {"'", '"'}:
            state = "string"
            quote = char
            index += 1
            continue
        if char == "/" and nxt == "/":
            out[index] = out[index + 1] = " "
            state = "line_comment"
            index += 2
            continue
        if char == "#":
            out[index] = " "
            state = "line_comment"
            index += 1
            continue
        if char == "/" and nxt == "*":
            out[index] = out[index + 1] = " "
            state = "block_comment"
            index += 2
            continue
        index += 1
    return "".join(out)


def written_security_headers(text: str) -> set[str]:
    """Return security-header names backed by a visible header-writing operation."""
    source = strip_comments(text)
    lowered = source.lower()
    if not _HEADER_WRITE.search(source):
        return set()
    return {header for header in SECURITY_HEADERS if header in lowered}


def has_enforcing_csp(text: str) -> bool:
    source = strip_comments(text)
    lowered = source.lower()
    if _CSP_PACKAGE.search(source):
        return True
    if "content-security-policy" not in lowered or not _HEADER_WRITE.search(source):
        return False
    without_report_only = re.sub(
        r"content-security-policy-report-only",
        "",
        lowered,
        flags=re.IGNORECASE,
    )
    return "content-security-policy" in without_report_only


def iter_project_texts(
    facts: Facts,
    *,
    current_path: str,
    current_content: str,
) -> Iterator[tuple[str, str]]:
    """Yield relevant project text without assuming Laravel's default directory layout."""
    current_norm = normalize_path(current_path)
    yielded = {current_norm}
    yield current_norm, current_content or ""

    root = Path(str(getattr(facts, "project_path", "") or "."))
    for raw_path in getattr(facts, "files", []) or []:
        relative = str(raw_path or "").replace("\\", "/")
        normalized = normalize_path(relative)
        if not normalized or normalized in yielded:
            continue
        suffix = Path(normalized).suffix.lower()
        if suffix not in _TEXT_SUFFIXES and not normalized.endswith(".htaccess"):
            continue
        yielded.add(normalized)
        candidate = root / relative
        try:
            if candidate.is_file() and candidate.stat().st_size <= 2_000_000:
                yield normalized, candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
