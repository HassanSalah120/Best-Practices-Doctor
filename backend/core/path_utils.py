"""
Path utilities.

We keep file paths in reports and facts as forward-slash relative paths for stability
across platforms and refactors.
"""

from __future__ import annotations


def normalize_rel_path(p: str) -> str:
    if not p:
        return p
    s = str(p).replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    # Collapse duplicate slashes.
    while "//" in s:
        s = s.replace("//", "/")
    return s

