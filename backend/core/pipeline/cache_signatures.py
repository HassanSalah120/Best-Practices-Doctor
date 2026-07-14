"""Stable signatures for configuration-dependent pipeline cache entries."""

from __future__ import annotations

import hashlib
import inspect
import json
from typing import Any


def stable_signature(value: Any, length: int = 24) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:length]


def implementation_signature(objects: list[Any], length: int = 24) -> str:
    """Hash loaded implementations so result caches cannot outlive rule edits."""
    sources: list[tuple[str, str, str]] = []
    for value in objects:
        cls = value if inspect.isclass(value) else type(value)
        module = str(getattr(cls, "__module__", "") or "")
        qualname = str(getattr(cls, "__qualname__", "") or "")
        try:
            source = inspect.getsource(cls)
        except (OSError, TypeError):
            source = repr(cls)
        sources.append((module, qualname, source))
    return stable_signature(sorted(sources), length=length)
