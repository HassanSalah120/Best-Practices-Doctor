"""Shared verification command inference."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def infer_verification_commands(project_path: Path) -> list[str]:
    project_path = Path(project_path)
    commands: list[str] = []

    composer = _read_json(project_path / "composer.json")
    if (project_path / "composer.json").exists():
        (project_path / "composer.json").read_text(encoding="utf-8", errors="ignore")

    if (project_path / "phpunit.xml").exists() or (project_path / "phpunit.xml.dist").exists():
        commands.append("php artisan test")
    require_dev = composer.get("require-dev") if isinstance(composer, dict) else {}
    require = composer.get("require") if isinstance(composer, dict) else {}
    composer_packages = set()
    if isinstance(require, dict):
        composer_packages.update(str(name).lower() for name in require)
    if isinstance(require_dev, dict):
        composer_packages.update(str(name).lower() for name in require_dev)
    if (project_path / "artisan").exists() and any(name.startswith("pestphp/pest") for name in composer_packages):
        commands.append("php artisan test --pest")
    if isinstance(composer, dict):
        scripts = composer.get("scripts") or {}
        if isinstance(scripts, dict):
            if "test" in scripts and "composer test" not in commands:
                commands.append("composer test")
            if "lint" in scripts:
                commands.append("composer run lint")

    package = _read_json(project_path / "package.json")
    if isinstance(package, dict):
        scripts = package.get("scripts") or {}
        if isinstance(scripts, dict):
            if "test" in scripts:
                commands.append("npm run test")
            if "tsc" in scripts:
                commands.append("npm run tsc")
            elif "typecheck" in scripts:
                commands.append("npm run typecheck")
            if "lint" in scripts:
                commands.append("npm run lint")

    if (project_path / "tsconfig.json").exists() and not commands:
        commands.append("npx tsc --noEmit")
    return commands or ["echo 'No verification commands detected'"]
