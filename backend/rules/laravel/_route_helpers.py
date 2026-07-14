"""Shared helpers for route classification.

Replaces hardcoded "routes/api.php" / "routes/web.php" path checks
with content-aware detection that works with any directory layout.
"""

from __future__ import annotations

from schemas.facts import RouteInfo


def normalize_route_path(fp: str | None) -> str:
    """Normalize route file path to lowercase with forward slashes."""
    if not fp:
        return ""
    return fp.replace("\\", "/").lower()


def is_api_route_file(route: RouteInfo | str) -> bool:
    """Check if a route was defined in an API route file.

    Accepts either a RouteInfo object or a raw path string.
    Uses multiple signals: path contains 'api', URI starts with 'api/',
    or middleware contains 'api'.
    """
    if isinstance(route, RouteInfo):
        fp = normalize_route_path(route.file_path)
        uri = str(route.uri or "").strip("/").lower()
        middleware = " ".join(str(m or "") for m in (getattr(route, "middleware", []) or []))
        if "api" in middleware.lower():
            return True
        if uri == "api" or uri.startswith("api/"):
            return True
        if _is_api_path(fp):
            return True
        return False
    # Raw path string
    return _is_api_path(normalize_route_path(route))


def is_web_route_file(route: RouteInfo | str) -> bool:
    """Check if a route was defined in a web route file.

    Defaults to True only for paths that are actually route files
    and not clearly API routes (safe default for security rules
    that target web routes).
    """
    if isinstance(route, RouteInfo):
        fp = normalize_route_path(route.file_path)
        if not _is_route_path(fp):
            return False
        uri = str(route.uri or "").strip("/").lower()
        middleware = " ".join(str(m or "") for m in (getattr(route, "middleware", []) or []))
        if "api" in middleware.lower():
            return False
        if uri == "api" or uri.startswith("api/"):
            return False
        if _is_api_path(fp):
            return False
        return True
    # Raw path string — only classify if it's actually a route file
    # and not an API route file.
    norm = normalize_route_path(route)
    if not _is_route_path(norm):
        return False
    return not _is_api_path(norm)


def _is_route_path(fp: str) -> bool:
    """Check if a normalized path is in a routes directory."""
    if not fp:
        return False
    return "/routes/" in fp or fp.startswith("routes/")


def _is_api_path(fp: str) -> bool:
    """Check if a normalized file path indicates an API route file.

    Must be in a routes directory and contain 'api' in the path.
    """
    if not fp:
        return False
    if not _is_route_path(fp):
        return False
    return "api" in fp


def is_config_path(fp: str) -> bool:
    """Check if a path is under a config/ directory.

    Catches both root-level config/foo.php and nested paths.
    """
    norm = normalize_route_path(fp)
    return norm.startswith("config/") or "/config/" in norm
