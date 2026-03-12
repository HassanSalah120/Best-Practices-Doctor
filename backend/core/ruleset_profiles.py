"""
Ruleset Profiles

Profiles are packaged YAML rulesets (startup/balanced/strict) that can be selected
per-user and persisted in app data settings (settings.json).

This module is intentionally small and filesystem-only:
- No scanning
- No rule engine coupling
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable


DEFAULT_PROFILE_NAMES: tuple[str, ...] = ("startup", "balanced", "strict")

_SAFE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


def _profile_dirs() -> list[Path]:
    # Prefer workspace-local rulesets/ if present (repo root or backend/ as cwd),
    # then fallback to packaged backend/rulesets/.
    dirs: list[Path] = []
    try:
        dirs.append(Path.cwd() / "rulesets")
    except Exception:
        pass
    try:
        backend_root = Path(__file__).resolve().parents[1]
        dirs.append(backend_root / "rulesets")
    except Exception:
        pass
    return dirs


def _is_safe_profile_name(name: str) -> bool:
    name = (name or "").strip().lower()
    return bool(name and _SAFE_NAME_RE.match(name))


def list_profiles() -> list[str]:
    """Return available profile names based on rulesets/*.yaml on disk.

    If none are found, return the known default profile names.
    """
    found: set[str] = set()
    for d in _profile_dirs():
        try:
            if not d.exists():
                continue
            for p in d.glob("*.yaml"):
                name = p.stem.strip().lower()
                if _is_safe_profile_name(name):
                    found.add(name)
        except Exception:
            continue

    if not found:
        return list(DEFAULT_PROFILE_NAMES)

    # Stable order: default names first (if present), then the rest.
    ordered: list[str] = []
    for n in DEFAULT_PROFILE_NAMES:
        if n in found:
            ordered.append(n)
    for n in sorted(found):
        if n not in ordered:
            ordered.append(n)
    return ordered


def get_profile_path(name: str) -> Path | None:
    """Return the YAML file path for a given profile, if present."""
    name = (name or "").strip().lower()
    if not _is_safe_profile_name(name):
        return None

    for d in _profile_dirs():
        try:
            p = d / f"{name}.yaml"
            if p.exists():
                return p
        except Exception:
            continue

    return None


def read_profile_yaml(name: str) -> str | None:
    """Read and return the raw YAML contents for a profile."""
    p = get_profile_path(name)
    if not p:
        return None
    try:
        return p.read_text(encoding="utf-8")
    except Exception:
        return None

