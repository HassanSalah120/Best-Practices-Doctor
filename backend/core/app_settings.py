"""
App Settings Store (User-scoped)

Persists small user preferences in the app data directory, e.g. the active ruleset profile.
This is intentionally separate from the ruleset YAML itself.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from config import ensure_app_data_dir


SETTINGS_FILENAME = "settings.json"


def _settings_path() -> Path:
    return ensure_app_data_dir() / SETTINGS_FILENAME


def load_settings() -> dict[str, Any]:
    p = _settings_path()
    try:
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8") or "{}") or {}
    except Exception:
        return {}
    return {}


def save_settings(data: dict[str, Any]) -> None:
    p = _settings_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def get_active_ruleset_profile(default: str = "startup") -> str:
    s = load_settings()
    v = str(s.get("active_profile") or "").strip().lower()
    return v or default


def set_active_ruleset_profile(name: str) -> None:
    s = load_settings()
    s["active_profile"] = str(name or "").strip().lower()
    save_settings(s)

