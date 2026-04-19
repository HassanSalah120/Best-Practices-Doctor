"""
Skip Link Missing Rule (hardened for shell/layout scope).
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class SkipLinkMissingRule(Rule):
    id = "skip-link-missing"
    name = "Skip Link Missing"
    description = "Detects shell/layout files without a valid skip-to-content link"
    category = Category.ACCESSIBILITY
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _ALLOWLIST_PATHS = (
        "/tests/",
        "/test/",
        "/__tests__/",
        "/stories/",
        "/storybook/",
        "/components/ui/",
    )
    _SHELL_PATH_PATTERNS = (
        "/layouts/",
        "/layout/",
        "/app.tsx",
        "/_app.tsx",
        "/_document.tsx",
    )
    _PAGE_PATH_MARKERS = ("/pages/", "/screens/", "/views/", "/components/")
    _SKIP_LINK_RE = re.compile(r"<a\b[^>]*href=['\"]#(?P<target>[A-Za-z0-9\-_:.]+)['\"][^>]*>", re.IGNORECASE)
    _MAIN_ID_RE = re.compile(r"<main\b[^>]*id=['\"](?P<id>[A-Za-z0-9\-_:.]+)['\"][^>]*>", re.IGNORECASE)
    _MAIN_ROLE_ID_RE = re.compile(r"<[^>]+\brole=['\"]main['\"][^>]*id=['\"](?P<id>[A-Za-z0-9\-_:.]+)['\"][^>]*>", re.IGNORECASE)
    _MAIN_ROLE_RE = re.compile(r"<[^>]+\brole=['\"]main['\"][^>]*>", re.IGNORECASE)

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._is_allowlisted_path(file_path):
            return []

        path_low = (file_path or "").lower().replace("\\", "/")
        content_text = content or ""
        if not self._is_shell_or_entry_file(path_low, content_text):
            return []

        main_targets: set[str] = set()
        for m in self._MAIN_ID_RE.finditer(content_text):
            main_targets.add((m.group("id") or "").strip())
        for m in self._MAIN_ROLE_ID_RE.finditer(content_text):
            main_targets.add((m.group("id") or "").strip())
        has_main_landmark = bool(main_targets) or bool(self._MAIN_ROLE_RE.search(content_text)) or ("<main" in content_text.lower())
        if not has_main_landmark:
            return []

        skip_targets = [(m.group("target") or "").strip() for m in self._SKIP_LINK_RE.finditer(content_text)]
        if not skip_targets:
            return [self._finding(file_path, 1, "missing_skip_link", "none", "none")]

        valid_target = False
        if not main_targets:
            # If no explicit main id but main landmark exists, allow conventional targets.
            valid_target = any(t in {"main", "content", "main-content"} for t in skip_targets)
        else:
            valid_target = any(t in main_targets for t in skip_targets)

        if valid_target:
            return []
        return [self._finding(file_path, 1, "invalid_skip_target", ",".join(skip_targets[:3]), ",".join(sorted(main_targets)[:3]))]

    def _finding(self, file_path: str, line: int, reason: str, skip_target: str, main_target: str) -> Finding:
        return self.create_finding(
            title="Shell/layout is missing a valid skip-to-content link",
            context=f"{file_path}:{line}:skip-link",
            file=file_path,
            line_start=line,
            description=(
                "Found a shell/layout structure with main content but no valid skip link target pairing."
            ),
            why_it_matters=(
                "WCAG bypass-blocks behavior requires keyboard users to skip repeated navigation and reach main content quickly."
            ),
            suggested_fix=(
                "Add a top-of-shell skip link with a target that matches your main content landmark id, "
                "for example `<a href=\"#main\" className=\"sr-only focus:not-sr-only\">Skip to main content</a>` "
                "and `<main id=\"main\">`."
            ),
            tags=["a11y", "wcag", "keyboard", "navigation", "skip-link"],
            confidence=0.9,
            evidence_signals=[
                f"reason={reason}",
                f"skip_target={skip_target}",
                f"main_target={main_target}",
            ],
        )

    def _is_shell_or_entry_file(self, path_low: str, content: str) -> bool:
        if any(marker in path_low for marker in self._SHELL_PATH_PATTERNS):
            return True
        if any(marker in path_low for marker in self._PAGE_PATH_MARKERS):
            return False
        # Fallback shell signal in mixed structures.
        return ("<main" in content.lower()) and ("<nav" in content.lower() or "sidebar" in content.lower())

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)

