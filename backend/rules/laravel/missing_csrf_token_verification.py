"""Evidence-driven CSRF coverage analysis for Laravel browser routes."""

from __future__ import annotations

import posixpath
import re
from pathlib import Path

from rules.base import Rule
from schemas.facts import Facts, RouteInfo
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


class MissingCsrfTokenVerificationRule(Rule):
    """Find session-authenticated mutations outside a CSRF-bearing route stack.

    The rule never treats missing metadata as proof by itself. It requires a
    browser/session authentication signal and resolves web/API registration,
    nested web includes, custom CSRF middleware groups, and configured explicit
    exemptions before reporting.
    """

    id = "missing-csrf-token-verification"
    name = "Session Mutation Missing CSRF Middleware"
    description = "Detects session-authenticated mutating routes outside a resolved CSRF middleware stack"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_livewire",
    ]
    severity_weight = 8
    confidence = "high"
    fix_suggestion = (
        "Register the route through a CSRF-bearing browser middleware group (normally `web`) or use an explicit "
        "token-authenticated API route. Do not add a CSRF exemption merely to silence this finding."
    )
    examples = {
        "bad": "Route::middleware('auth')->post('/profile', [ProfileController::class, 'update']);",
        "good": "Route::middleware(['web', 'auth'])->post('/profile', [ProfileController::class, 'update']);",
    }
    priority = 1
    group = "Sensitive Data"
    applies_to = ["route", "middleware"]
    references = ["OWASP A01:2021 - Broken Access Control", "CWE-352"]
    related_rules = ["csrf-exception-wildcard-risk"]
    false_positive_notes = (
        "Only session/browser-authenticated routes are evaluated; bearer/token API routes and explicit exemptions are excluded."
    )
    detection_type = "cross-file"
    analysis_cost = "high"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "security", "concern": "csrf-token-verification"}

    _MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
    _SESSION_MIDDLEWARE = {
        "auth",
        "auth:web",
        "guest",
        "guest:web",
        "verified",
        "password.confirm",
        "session",
        "authenticate.session",
    }
    _TOKEN_MIDDLEWARE = {
        "api",
        "auth:api",
        "auth:sanctum",
        "auth:passport",
        "passport",
        "token",
        "bearer",
        "oauth",
    }
    _TOKEN_PARAMETERIZED_MIDDLEWARE = ("passport:", "token:", "bearer:", "oauth:")

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        php_sources = self._load_candidate_php_sources(facts)
        web_route_includes = self._discover_web_route_includes(facts, php_sources)
        configured_exemptions = self._discover_csrf_exempt_patterns(facts, php_sources)
        findings: list[Finding] = []

        for route in getattr(facts, "routes", []) or []:
            if str(route.method or "").upper() not in self._MUTATING_METHODS:
                continue
            uri = str(route.uri or "").lower().strip("/")
            middleware = [str(item or "").strip().lower() for item in (route.middleware or []) if str(item or "").strip()]

            if self._matches_exempt_pattern(uri, configured_exemptions):
                continue
            if self._has_explicit_csrf_removal(middleware):
                # This is an intentional per-route exemption. Broad exemption
                # safety is evaluated by csrf-exception-wildcard-risk.
                continue
            if self._has_token_auth(route, middleware):
                continue

            in_web_stack = self._has_csrf_stack(route, middleware, web_route_includes)
            if in_web_stack:
                continue

            session_signals = sorted(
                token
                for token in middleware
                if token in self._SESSION_MIDDLEWARE
                or token.startswith("auth:web")
                or token.startswith("guest:web")
            )
            # Absence of `web` metadata alone is not a finding. A session signal
            # is the positive evidence that CSRF is required at this boundary.
            if not session_signals:
                continue

            line = int(getattr(route, "line_number", 1) or 1)
            findings.append(
                self.create_finding(
                    title="Session-authenticated mutation is outside a CSRF middleware stack",
                    context=f"{route.method} {route.uri}",
                    file=str(route.file_path or ""),
                    line_start=line,
                    description=(
                        f"`{route.method} {route.uri}` uses browser/session middleware "
                        f"({', '.join(session_signals)}) but its resolved route registration has no `web` or CSRF middleware."
                    ),
                    why_it_matters=(
                        "Browsers automatically attach session cookies. Without CSRF validation, another origin can submit "
                        "a state-changing request as the signed-in user."
                    ),
                    suggested_fix=self.fix_suggestion,
                    confidence=0.94,
                    tags=["security", "csrf", "laravel", "middleware", "cross-file"],
                    related_files=[str(route.file_path)] if route.file_path else [],
                    evidence_signals=[
                        "mutating_route=true",
                        "session_authentication=true",
                        "resolved_csrf_stack=false",
                        "token_authentication=false",
                        f"session_signals={','.join(session_signals)}",
                    ],
                ),
            )
        return findings

    def _has_csrf_stack(
        self,
        route: RouteInfo,
        middleware: list[str],
        web_route_includes: set[str],
    ) -> bool:
        if any(
            token == "web"
            or "verifycsrftoken" in token
            or "validatecsrftoken" in token
            for token in middleware
            if not token.startswith("without:")
        ):
            return True
        normalized = self._normalize_route_path(str(route.file_path or ""))
        if normalized.endswith("routes/web.php") or normalized in web_route_includes:
            return True
        return self._is_in_web_include_chain(route.file_path, web_route_includes)

    def _has_token_auth(self, route: RouteInfo, middleware: list[str]) -> bool:
        if any(
            token in self._TOKEN_MIDDLEWARE or token.startswith(self._TOKEN_PARAMETERIZED_MIDDLEWARE)
            for token in middleware
        ):
            return True
        uri = str(route.uri or "").strip("/").lower()
        if uri == "api" or uri.startswith("api/"):
            return True
        path = self._normalize_route_path(str(route.file_path or ""))
        name = Path(path).name.lower()
        return name == "api.php" or name.startswith("api-") or name.startswith("api_")

    @staticmethod
    def _has_explicit_csrf_removal(middleware: list[str]) -> bool:
        return any(
            token.startswith("without:")
            and ("verifycsrftoken" in token or "validatecsrftoken" in token)
            for token in middleware
        )

    def _discover_web_route_includes(
        self,
        facts: Facts,
        php_sources: list[tuple[str, str]] | None = None,
    ) -> set[str]:
        root = Path(getattr(facts, "project_path", "") or ".")
        configured = self._discover_configured_web_route_files(
            php_sources if php_sources is not None else self._load_candidate_php_sources(facts),
        )
        candidates = {
            self._normalize_route_path(str(path))
            for path in (getattr(facts, "files", []) or [])
            if self._normalize_route_path(str(path)).endswith("routes/web.php")
        }
        candidates.update(
            path
            for path in ("routes/web.php", "src/routes/web.php", "app/routes/web.php")
            if (root / path).exists()
        )
        candidates.update(configured)
        included: set[str] = set(configured)
        for relative_path in sorted(candidates):
            included.update(self._collect_route_includes(root, relative_path, set()))
        return included

    def _discover_configured_web_route_files(
        self,
        php_sources: list[tuple[str, str]],
    ) -> set[str]:
        """Resolve explicit web registrations without assuming routes/web.php."""
        configured: set[str] = set()
        for source_path, text in php_sources:

            # Laravel 11+ Application::configure()->withRouting(web: ...).
            for match in re.finditer(
                r"\bweb\s*:\s*(?:base_path\s*\(\s*)?['\"](?P<path>[^'\"]+\.php)['\"]",
                text,
                re.IGNORECASE,
            ):
                configured.add(self._normalize_route_path(match.group("path")))

            # RouteServiceProvider and custom registrars using a named web
            # middleware group followed by ->group(<route file>).
            for match in re.finditer(
                r"middleware\s*\([^)]*['\"]web['\"][^;]{0,500}?->group\s*\(\s*"
                r"(?:base_path\s*\(\s*)?['\"](?P<path>[^'\"]+\.php)['\"]",
                text,
                re.IGNORECASE | re.DOTALL,
            ):
                configured.add(self._normalize_route_path(match.group("path")))
        return {path for path in configured if path}

    def _load_candidate_php_sources(self, facts: Facts) -> list[tuple[str, str]]:
        """Read each relevant PHP source at most once per rule execution."""
        root = Path(getattr(facts, "project_path", "") or ".")
        candidates = [str(path) for path in (getattr(facts, "files", []) or [])]
        for fallback in ("bootstrap/app.php", "app/Providers/RouteServiceProvider.php"):
            if fallback not in candidates and (root / fallback).exists():
                candidates.append(fallback)
        sources: list[tuple[str, str]] = []
        seen: set[str] = set()
        for rel_path in candidates:
            normalized = self._normalize_route_path(rel_path)
            if normalized in seen or not normalized.endswith(".php"):
                continue
            seen.add(normalized)
            try:
                text = (root / rel_path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            sources.append((rel_path, text))
        return sources

    def _collect_route_includes(self, root: Path, relative_path: str, seen: set[str]) -> set[str]:
        normalized = self._normalize_route_path(relative_path)
        if normalized in seen:
            return set()
        seen.add(normalized)
        file_path = root / normalized
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return set()

        matches: set[str] = set()
        for match in re.finditer(
            r"(?:(?P<base>base_path)\s*\(\s*)?(?:(?P<dir>__DIR__)\s*\.\s*)?['\"](?P<path>[^'\"]+\.php)['\"]",
            text,
            re.IGNORECASE,
        ):
            raw = str(match.group("path") or "").replace("\\", "/")
            if match.group("dir"):
                # In `__DIR__ . '/auth.php'` the leading slash is a PHP
                # concatenation separator, not a filesystem-root marker.
                child = posixpath.normpath(posixpath.join(posixpath.dirname(normalized), raw.lstrip("/")))
            else:
                child = posixpath.normpath(raw.lstrip("./"))
            child = self._normalize_route_path(child)
            if not child or child == normalized:
                continue
            matches.add(child)
            # The route facts themselves are sufficient evidence that a
            # registered child exists. Only recursive source inspection needs
            # the physical file (fixtures and partial scans may omit it).
            if (root / child).is_file():
                matches.update(self._collect_route_includes(root, child, seen))
        return matches

    def _discover_csrf_exempt_patterns(
        self,
        facts: Facts,
        php_sources: list[tuple[str, str]] | None = None,
    ) -> list[str]:
        patterns: list[str] = []
        sources = php_sources if php_sources is not None else self._load_candidate_php_sources(facts)
        for _rel_path, text in sources:
            if "validateCsrfTokens" not in text and "verifyCsrfTokens" not in text:
                continue
            for match in re.finditer(
                r"(?:validate|verify)CsrfTokens\s*\(\s*except\s*:\s*\[(?P<body>.*?)\]\s*\)",
                text,
                re.IGNORECASE | re.DOTALL,
            ):
                patterns.extend(
                    value.strip().lower().lstrip("/")
                    for value in re.findall(r"['\"]([^'\"]+)['\"]", match.group("body") or "")
                )
        return sorted(set(patterns))

    def _matches_exempt_pattern(self, uri: str, patterns: list[str]) -> bool:
        normalized_uri = str(uri or "").strip("/").lower()
        for pattern in patterns:
            normalized = str(pattern or "").strip("/").lower()
            if not normalized:
                continue
            if normalized.endswith("*"):
                prefix = normalized[:-1].rstrip("/")
                if normalized_uri == prefix or normalized_uri.startswith(prefix + "/"):
                    return True
            elif normalized_uri == normalized:
                return True
        return False

    def _is_in_web_include_chain(self, route_file_path: str | None, includes: set[str]) -> bool:
        normalized = self._normalize_route_path(str(route_file_path or ""))
        return normalized in includes or any(normalized.endswith("/" + item) for item in includes)

    @staticmethod
    def _normalize_route_path(value: str) -> str:
        return str(value or "").replace("\\", "/").strip().lower().lstrip("./")
