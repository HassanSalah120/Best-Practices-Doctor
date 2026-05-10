"""
Shared helpers for dependency security version checks.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True)
class DependencyAdvisory:
    package: str
    minimum_version: str
    ecosystem: str
    summary: str


def _default_catalog() -> dict[str, dict[str, DependencyAdvisory]]:
    return {
        "composer": {
            "league/commonmark": DependencyAdvisory(
                package="league/commonmark",
                minimum_version="2.8.1",
                ecosystem="composer",
                summary="Known security issues have affected older `league/commonmark` releases.",
            ),
        },
        "npm": {
            "dompurify": DependencyAdvisory(
                package="dompurify",
                minimum_version="3.3.2",
                ecosystem="npm",
                summary="Older `dompurify` releases have had security-impacting bypasses and patch releases.",
            ),
        },
    }


@lru_cache(maxsize=1)
def load_dependency_advisory_catalog() -> dict[str, dict[str, DependencyAdvisory]]:
    catalog = _default_catalog()
    path = Path(__file__).with_name("dependency_advisories.json")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return catalog

    if not isinstance(raw, dict):
        return catalog

    out: dict[str, dict[str, DependencyAdvisory]] = {"composer": {}, "npm": {}}
    for ecosystem in ("composer", "npm"):
        items = raw.get(ecosystem)
        if not isinstance(items, dict):
            out[ecosystem] = dict(catalog.get(ecosystem, {}))
            continue
        for package, entry in items.items():
            if not isinstance(entry, dict):
                continue
            minimum = str(entry.get("minimum_version") or "").strip()
            summary = str(entry.get("summary") or "").strip()
            pkg = str(package or "").strip()
            if not pkg or not minimum or not summary:
                continue
            out[ecosystem][pkg] = DependencyAdvisory(
                package=pkg,
                minimum_version=minimum,
                ecosystem=ecosystem,
                summary=summary,
            )
        if not out[ecosystem]:
            out[ecosystem] = dict(catalog.get(ecosystem, {}))
    return out


_CATALOG = load_dependency_advisory_catalog()
COMPOSER_ADVISORIES: dict[str, DependencyAdvisory] = _CATALOG["composer"]
NPM_ADVISORIES: dict[str, DependencyAdvisory] = _CATALOG["npm"]


def parse_json_object(content: str) -> dict | None:
    try:
        data = json.loads(content or "")
    except Exception:
        return None
    if isinstance(data, dict):
        return data
    return None


def normalize_version(raw: str | None) -> tuple[int, int, int, int] | None:
    text = str(raw or "").strip()
    if not text:
        return None

    if any(token in text for token in ("||", "*", "x", "X")):
        return None

    text = text.replace(",", " ")
    match = re.search(r"(\d+(?:\.\d+){0,3})", text.lstrip("vV^~<>=! "))
    if not match:
        return None

    parts = [int(part) for part in match.group(1).split(".")]
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts[:4])


def is_version_below_minimum(current: str | None, minimum: str) -> bool:
    cur = normalize_version(current)
    min_v = normalize_version(minimum)
    if cur is None or min_v is None:
        return False
    return cur < min_v


def find_line_number(content: str, needle: str) -> int:
    text = content or ""
    idx = text.lower().find(str(needle or "").lower())
    if idx < 0:
        return 1
    return text.count("\n", 0, idx) + 1


def collect_composer_packages(data: dict) -> dict[str, str]:
    packages: dict[str, str] = {}
    for key in ("packages", "packages-dev"):
        items = data.get(key)
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            version = str(item.get("version") or "").strip()
            if name and version:
                packages[name] = version
    return packages


def collect_composer_constraints(data: dict) -> dict[str, str]:
    packages: dict[str, str] = {}
    for key in ("require", "require-dev"):
        group = data.get(key)
        if not isinstance(group, dict):
            continue
        for name, version in group.items():
            pkg = str(name or "").strip()
            ver = str(version or "").strip()
            if pkg and ver:
                packages[pkg] = ver
    return packages


def collect_npm_packages(data: dict) -> dict[str, str]:
    packages: dict[str, str] = {}

    lock_packages = data.get("packages")
    if isinstance(lock_packages, dict):
        for path, item in lock_packages.items():
            if not isinstance(item, dict):
                continue
            raw_path = str(path or "")
            if not raw_path.startswith("node_modules/"):
                continue
            name = raw_path.split("node_modules/", 1)[1]
            version = str(item.get("version") or "").strip()
            if name and version:
                packages[name] = version

    if packages:
        return packages

    def _walk_deps(tree: dict) -> None:
        deps = tree.get("dependencies")
        if not isinstance(deps, dict):
            return
        for name, item in deps.items():
            if not isinstance(item, dict):
                continue
            pkg = str(name or "").strip()
            version = str(item.get("version") or "").strip()
            if pkg and version and pkg not in packages:
                packages[pkg] = version
            _walk_deps(item)

    _walk_deps(data)
    return packages


def collect_npm_constraints(data: dict) -> dict[str, str]:
    packages: dict[str, str] = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        group = data.get(key)
        if not isinstance(group, dict):
            continue
        for name, version in group.items():
            pkg = str(name or "").strip()
            ver = str(version or "").strip()
            if pkg and ver:
                packages[pkg] = ver
    return packages
