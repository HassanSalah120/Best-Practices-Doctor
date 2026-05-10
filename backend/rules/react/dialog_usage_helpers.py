from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

_IMPORT_RE = re.compile(
    r"import\s+(?P<spec>[\s\S]*?)\s+from\s+['\"](?P<src>[^'\"]+)['\"]\s*;?",
    re.MULTILINE,
)
_IDENTIFIER_RE = re.compile(r"^[A-Z][A-Za-z0-9_]*$")
_JSX_COMPONENT_TAG_RE = re.compile(r"<(?P<tag>[A-Z][A-Za-z0-9_]*)\b")
_SHARED_DIALOG_SOURCE_HINTS = (
    "/modal",
    "/dialog",
    "/alertdialog",
    "@/components/ui/modal",
    "@/components/ui/dialog",
    "@/components/modal",
    "@/components/dialog",
    "@headlessui/react",
    "@radix-ui/react-dialog",
    "@radix-ui/react-alert-dialog",
    "react-aria-components",
    "@react-aria/overlays",
)
_LOCAL_IMPORT_PREFIXES = ("./", "../", "@/")
_ALIAS_ROOTS = ("resources/js", "src", "frontend/src")
_RESOLVED_EXTENSIONS = (".tsx", ".ts", ".jsx", ".js")
_MAX_DIALOG_TRACE_DEPTH = 4


def imported_symbol_sources(text: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for match in _IMPORT_RE.finditer(text or ""):
        raw_spec = str(match.group("spec") or "").strip()
        source = str(match.group("src") or "").strip()
        if not raw_spec or not source:
            continue

        default_part = raw_spec
        named_block = ""
        if "," in raw_spec:
            default_part, named_block = raw_spec.split(",", 1)
        elif raw_spec.startswith("{"):
            default_part = ""
            named_block = raw_spec

        default_symbol = default_part.strip()
        if _IDENTIFIER_RE.match(default_symbol):
            mapping[default_symbol] = source

        named_match = re.search(r"\{(?P<body>[^}]*)\}", named_block)
        if not named_match:
            continue
        for token in (named_match.group("body") or "").split(","):
            token = token.strip()
            if not token:
                continue
            local_name = token
            if " as " in token:
                _, local_name = token.split(" as ", 1)
            local_name = local_name.strip()
            if _IDENTIFIER_RE.match(local_name):
                mapping[local_name] = source
    return mapping


def is_shared_dialog_source(source: str) -> bool:
    normalized = str(source or "").replace("\\", "/").lower()
    return any(hint in normalized for hint in _SHARED_DIALOG_SOURCE_HINTS)


def _is_local_component_source(source: str) -> bool:
    normalized = str(source or "").strip()
    return bool(normalized) and normalized.startswith(_LOCAL_IMPORT_PREFIXES)


def _unique_paths(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    unique: list[Path] = []
    for path in paths:
        key = str(path).lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def _candidate_module_paths(base: Path) -> list[Path]:
    candidates = [base]
    if not base.suffix:
        for ext in _RESOLVED_EXTENSIONS:
            candidates.append(base.with_suffix(ext))
            candidates.append(base / f"index{ext}")
    return _unique_paths(candidates)


def _resolve_project_root(project_path: str | None) -> Path:
    if project_path:
        try:
            return Path(project_path).resolve()
        except OSError:
            pass
    return Path.cwd().resolve()


def _resolve_import_candidates(source: str, importer_file_path: str | None, project_path: str | None) -> list[Path]:
    normalized = str(source or "").strip()
    if not _is_local_component_source(normalized):
        return []

    project_root = _resolve_project_root(project_path)
    importer_path = Path(importer_file_path or "")
    if not importer_path.is_absolute():
        importer_path = (project_root / importer_path).resolve()

    candidates: list[Path] = []
    if normalized.startswith(("./", "../")):
        candidates.extend(_candidate_module_paths((importer_path.parent / normalized).resolve()))
    elif normalized.startswith("@/"):
        relative = normalized[2:]
        for alias_root in _ALIAS_ROOTS:
            candidates.extend(_candidate_module_paths((project_root / alias_root / relative).resolve()))
        candidates.extend(_candidate_module_paths((project_root / relative).resolve()))

    return [path for path in _unique_paths(candidates) if path.is_file()]


@lru_cache(maxsize=512)
def _read_text(path_str: str) -> str:
    path = Path(path_str)
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            return path.read_text(encoding="utf-8-sig")
        except OSError:
            return ""
    except OSError:
        return ""


def _rendered_component_tags(text: str) -> list[str]:
    return [match.group("tag") for match in _JSX_COMPONENT_TAG_RE.finditer(text or "")]


def _file_uses_shared_dialog_component(path: Path, project_path: str | None, depth: int, seen: set[str]) -> bool:
    if depth > _MAX_DIALOG_TRACE_DEPTH:
        return False
    key = str(path.resolve()).lower()
    if key in seen:
        return False
    seen.add(key)

    text = _read_text(str(path))
    if not text:
        return False

    rendered_tags = _rendered_component_tags(text)
    imported = imported_symbol_sources(text)
    if any(is_shared_dialog_source(imported.get(tag, "")) for tag in rendered_tags):
        return True

    for tag in rendered_tags:
        source = imported.get(tag, "")
        if not _is_local_component_source(source):
            continue
        for candidate in _resolve_import_candidates(source, str(path), project_path):
            if _file_uses_shared_dialog_component(candidate, project_path, depth + 1, seen):
                return True
    return False


def _tag_uses_shared_dialog(
    tag: str,
    imported: dict[str, str],
    *,
    file_path: str | None,
    project_path: str | None,
) -> bool:
    source = imported.get(tag, "")
    if is_shared_dialog_source(source):
        return True
    if not _is_local_component_source(source) or not file_path:
        return False
    for candidate in _resolve_import_candidates(source, file_path, project_path):
        if _file_uses_shared_dialog_component(candidate, project_path, depth=1, seen=set()):
            return True
    return False


def tags_are_shared_dialog_consumers(
    tags: list[str],
    text: str,
    *,
    file_path: str | None = None,
    project_path: str | None = None,
) -> bool:
    imported = imported_symbol_sources(text)
    component_tags = [tag for tag in tags if tag and tag[:1].isupper()]
    if not component_tags:
        return False
    return all(
        _tag_uses_shared_dialog(
            tag,
            imported,
            file_path=file_path,
            project_path=project_path,
        )
        for tag in component_tags
    )
