"""Shared Tailwind-aware lexical analysis.

The helpers recognize static class fragments in JSX/HTML attributes and common
composition helpers without depending on a specific source directory. They
only return literals whose owning expression is executable code, so examples
inside comments and ordinary strings are ignored.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable
import re

from core.source_masking import mask_comments_and_strings
from schemas.facts import Facts


_CLASS_ATTRIBUTE_RE = re.compile(r"\b(?:className|class)\s*=", re.IGNORECASE)
_CLASS_HELPER_RE = re.compile(r"\b(?:cn|clsx|classNames|classnames|twMerge|cva|tv)\s*\(")
_TAILWIND_ONLY_SIGNAL_RE = re.compile(
    r"(?:^|\s)(?:[!\-]?(?:[a-z0-9-]+:|\[[^\]]+\]:)*)"
    r"(?:[a-z-]+-\[[^\]]+\]|motion-(?:safe|reduce):\S+|appearance-none|animate-[a-z0-9-]+|transition-(?:all|transform))(?:\s|$)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class StaticClassValue:
    line: int
    value: str
    source: str


@dataclass(frozen=True)
class OpeningTag:
    line: int
    name: str
    attributes: str


def has_tailwind_evidence(facts: Facts, content: str = "") -> bool:
    packages = {
        str(name or "").lower()
        for name in (getattr(facts, "npm_packages", {}) or {}).keys()
    }
    if any(name == "tailwindcss" or name.startswith("@tailwindcss/") for name in packages):
        return True
    if _TAILWIND_ONLY_SIGNAL_RE.search(content or ""):
        return True
    if any(
        _TAILWIND_ONLY_SIGNAL_RE.search(f" {item.value} ")
        for item in iter_static_class_values(content or "")
    ):
        return True
    paths = [str(path or "").replace("\\", "/").lower() for path in (getattr(facts, "files", []) or [])]
    return any(
        path.rsplit("/", 1)[-1].startswith(("tailwind.config.", "tailwind.config"))
        for path in paths
    )


def iter_static_class_values(content: str) -> Iterable[StaticClassValue]:
    text = content or ""
    code = mask_comments_and_strings(text)
    seen: set[tuple[int, str]] = set()

    for match in _CLASS_ATTRIBUTE_RE.finditer(code):
        parsed = _parse_attribute_value(text, match.end())
        if parsed is None:
            continue
        value, offset = parsed
        value = _static_template_text(value).strip()
        if not value or not _looks_like_class_list(value):
            continue
        key = (offset, value)
        if key in seen:
            continue
        seen.add(key)
        yield StaticClassValue(_line_of_offset(text, offset), value, "class-attribute")

    for match in _CLASS_HELPER_RE.finditer(code):
        close = _balanced_close(text, match.end() - 1, "(", ")")
        if close is None:
            continue
        call_body = text[match.end():close]
        call_offset = match.end()
        for relative_offset, value, quote in _iter_string_literals(call_body):
            value = _static_template_text(value).strip() if quote == "`" else value.strip()
            if not value or not _looks_like_class_list(value):
                continue
            offset = call_offset + relative_offset
            key = (offset, value)
            if key in seen:
                continue
            seen.add(key)
            yield StaticClassValue(_line_of_offset(text, offset), value, "class-helper")


def split_tailwind_tokens(class_value: str) -> list[str]:
    """Split a static class list while preserving arbitrary-value syntax."""
    return [token for token in re.split(r"\s+", (class_value or "").strip()) if _looks_like_tailwind_token(token)]


def tailwind_base_utility(token: str) -> str:
    """Remove variants and important/negative prefixes from a utility token."""
    parts: list[str] = []
    current: list[str] = []
    square_depth = 0
    paren_depth = 0
    for char in str(token or ""):
        if char == "[":
            square_depth += 1
        elif char == "]":
            square_depth = max(0, square_depth - 1)
        elif char == "(":
            paren_depth += 1
        elif char == ")":
            paren_depth = max(0, paren_depth - 1)
        if char == ":" and square_depth == 0 and paren_depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts[-1].lstrip("!-")


def tailwind_variants(token: str) -> list[str]:
    base = tailwind_base_utility(token)
    prefix = str(token or "")[: max(0, len(str(token or "")) - len(base))]
    return [part.lower() for part in prefix.split(":") if part]


def iter_opening_tags(content: str, names: set[str]) -> Iterable[OpeningTag]:
    """Yield JSX/HTML opening tags, ignoring `>` inside expressions/quotes."""
    text = content or ""
    code = mask_comments_and_strings(text)
    wanted = {name.lower() for name in names}
    pattern = re.compile(r"<\s*([A-Za-z][\w.-]*)\b")
    for match in pattern.finditer(code):
        name = str(match.group(1) or "").lower()
        if name not in wanted:
            continue
        start = match.end()
        end = _tag_end(text, start)
        if end is None:
            continue
        yield OpeningTag(_line_of_offset(text, match.start()), name, text[start:end])


def _parse_attribute_value(text: str, offset: int) -> tuple[str, int] | None:
    index = _skip_space(text, offset)
    if index >= len(text):
        return None
    if text[index] in {"'", '"', "`"}:
        parsed = _parse_string(text, index)
        return (parsed[0], index) if parsed else None
    if text[index] != "{":
        return None
    index = _skip_space(text, index + 1)
    if index >= len(text) or text[index] not in {"'", '"', "`"}:
        return None
    parsed = _parse_string(text, index)
    return (parsed[0], index) if parsed else None


def _iter_string_literals(text: str) -> Iterable[tuple[int, str, str]]:
    code = mask_comments_and_strings(text)
    index = 0
    while index < len(text):
        if code[index] != " " or text[index] not in {"'", '"', "`"}:
            index += 1
            continue
        parsed = _parse_string(text, index)
        if parsed is None:
            index += 1
            continue
        value, end = parsed
        yield index, value, text[index]
        index = end


def _parse_string(text: str, start: int) -> tuple[str, int] | None:
    quote = text[start]
    index = start + 1
    chars: list[str] = []
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            chars.extend([char, text[index + 1]])
            index += 2
            continue
        if char == quote:
            return "".join(chars), index + 1
        chars.append(char)
        index += 1
    return None


def _static_template_text(value: str) -> str:
    return re.sub(r"\$\{.*?\}", " ", value or "", flags=re.DOTALL)


def _looks_like_class_list(value: str) -> bool:
    tokens = [token for token in re.split(r"\s+", value.strip()) if token]
    return bool(tokens) and any(_looks_like_tailwind_token(token) for token in tokens)


def _looks_like_tailwind_token(token: str) -> bool:
    value = str(token or "").strip().strip(",")
    if not value or any(char in value for char in "{};'\""):
        return False
    if "[" in value and "]" not in value:
        return False
    base = tailwind_base_utility(value).lstrip("-")
    return bool(
        re.match(
            r"^(?:[a-z][a-z0-9-]*)(?:-|$|\[)",
            base,
            re.IGNORECASE,
        )
    )


def _balanced_close(text: str, start: int, opener: str, closer: str) -> int | None:
    if start < 0 or start >= len(text) or text[start] != opener:
        return None
    depth = 0
    quote = ""
    escaped = False
    index = start
    while index < len(text):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
        elif char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _tag_end(text: str, start: int) -> int | None:
    brace_depth = 0
    quote = ""
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            quote = char
        elif char == "{":
            brace_depth += 1
        elif char == "}":
            brace_depth = max(0, brace_depth - 1)
        elif char == ">" and brace_depth == 0:
            return index
    return None


def _skip_space(text: str, index: int) -> int:
    while index < len(text) and text[index].isspace():
        index += 1
    return index


def _line_of_offset(content: str, offset: int) -> int:
    return (content or "").count("\n", 0, offset) + 1
