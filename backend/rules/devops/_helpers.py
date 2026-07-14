from __future__ import annotations

import re
from pathlib import Path

from schemas.facts import Facts


def project_root(facts: Facts) -> Path:
    return Path(getattr(facts, "project_path", "") or ".").resolve()


def read_project_file(facts: Facts, relative_path: str) -> str:
    path = project_root(facts) / relative_path
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def project_file_exists(facts: Facts, relative_path: str) -> bool:
    return (project_root(facts) / relative_path).exists()


def line_for_key(content: str, key: str) -> int:
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=", re.IGNORECASE | re.MULTILINE)
    match = pattern.search(content or "")
    if not match:
        return 1
    return (content or "").count("\n", 0, match.start()) + 1


def parse_env_keys(content: str) -> set[str]:
    keys: set[str] = set()
    for line in (content or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key = stripped.split("=", 1)[0].strip()
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            keys.add(key)
    return keys


def env_value(content: str, key: str) -> str | None:
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=\s*(?P<value>.*?)\s*$", re.IGNORECASE | re.MULTILINE)
    match = pattern.search(content or "")
    if not match:
        return None
    return str(match.group("value") or "").strip().strip("'\"").lower()


def iter_project_files(facts: Facts, pattern: str) -> list[Path]:
    root = project_root(facts)
    try:
        return [
            path
            for path in root.rglob(pattern)
            if not any(part in {"vendor", "node_modules", ".git"} for part in path.relative_to(root).parts)
        ]
    except Exception:
        return []


def rel_path(facts: Facts, path: Path) -> str:
    try:
        return path.resolve().relative_to(project_root(facts)).as_posix()
    except Exception:
        return path.as_posix()


def is_laravel_project(facts: Facts) -> bool:
    root = project_root(facts)
    composer = read_project_file(facts, "composer.json").lower()
    if "laravel/framework" in composer:
        return True
    if (root / "artisan").exists():
        return True
    files = {str(path or "").replace("\\", "/").lower() for path in (getattr(facts, "files", []) or [])}
    return bool(
        any("/routes/" in path for path in files)
        or any("/http/" in path or "/http/controllers/" in path for path in files)
    )
