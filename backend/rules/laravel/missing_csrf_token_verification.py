"""
Missing CSRF Token Verification Rule

Detects routes that should have CSRF protection but don't.
"""

from __future__ import annotations

import re
from pathlib import Path

from schemas.facts import Facts, RouteInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class MissingCsrfTokenVerificationRule(Rule):
    id = "missing-csrf-token-verification"
    name = "Missing CSRF Token Verification"
    description = "Detects routes missing CSRF protection that should have it"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_livewire",
    ]

    # HTTP methods that modify state and need CSRF protection
    _MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

    # Routes that legitimately don't need CSRF
    _EXEMPT_ROUTE_PATTERNS = {
        "api/*",           # API routes use token auth, not CSRF
        "webhook/*",       # Webhooks from external services
        "webhooks/*",      # Webhooks from external services
        "stripe/*",        # Payment webhooks
        "payment/*",       # Payment callbacks
        "oauth/*",         # OAuth callbacks
        "login",           # Login (has its own protection)
        "logout",          # Logout
        "register",        # Registration
        "password/*",      # Password reset
        "forgot-password", # Laravel auth scaffold
        "reset-password",  # Laravel auth scaffold
        "confirm-password",# Laravel auth scaffold
        "email/*",         # Email verification
        "sanctum/*",       # Sanctum API
        "broadcasting/*",  # Broadcasting auth
    }

    # Middleware that explicitly signals CSRF protection in the route metadata we have.
    _CSRF_MIDDLEWARE = {"web", "verifycsrftoken"}

    # Middleware that explicitly disables CSRF or uses alternative auth
    _CSRF_EXEMPT_MIDDLEWARE = {"throttle", "api"}

    # Route file patterns - routes in web.php have CSRF by default
    _WEB_ROUTES_FILE = "routes/web.php"

    # Route files that don't have CSRF by default
    _API_ROUTES_FILES = {"routes/api.php", "routes/auth.php"}
    _AUTH_ROUTE_HINTS = {
        "forgot-password",
        "reset-password",
        "confirm-password",
        "verify-email",
        "email/verification-notification",
        "two-factor-challenge",
        "two-factor-challenge/email",
    }

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        web_route_includes = self._discover_web_route_includes(facts)
        csrf_exempt_patterns = self._discover_csrf_exempt_patterns(facts)

        # Group routes by URI for analysis
        web_routes = [r for r in facts.routes if r.method.upper() in self._MUTATING_METHODS]

        for route in web_routes:
            # Skip exempt routes
            uri_lower = (route.uri or "").lower().strip("/")
            if self._is_exempt_route(uri_lower):
                continue
            if self._matches_exempt_pattern(uri_lower, csrf_exempt_patterns):
                continue
            if self._is_auth_scaffold_route(route, uri_lower, web_route_includes):
                continue

            # Check middleware
            middleware = [m.lower() for m in route.middleware or []]

            # API routes don't need CSRF (they use token auth)
            if "api" in middleware:
                continue

            # Require an explicit CSRF/web signal in the captured middleware metadata.
            has_web_middleware = any(
                m == "web" or "verifycsrftoken" in m or m.endswith(":web")
                for m in middleware
            )

            # Check if route is in web.php (has CSRF by default in Laravel)
            is_in_web_routes = route.file_path and "routes/web.php" in route.file_path.lower()

            # Check if route explicitly excludes CSRF
            has_csrf_exempt = any(
                "csrf" in m and ("except" in m or "exclude" in m)
                for m in middleware
            )

            # Explicit CSRF signal is enough.
            if has_web_middleware:
                continue

            # If it explicitly exempts CSRF, skip
            if has_csrf_exempt:
                continue

            # Empty middleware in routes/web.php is usually safe because Laravel applies the
            # web group implicitly. Once route middleware is explicitly present, require the
            # fact model to include a CSRF signal instead of assuming inheritance.
            if is_in_web_routes and not middleware:
                continue
            if self._is_in_web_include_chain(route.file_path, web_route_includes):
                continue

            # This is a state-changing route without CSRF protection
            findings.append(
                self.create_finding(
                    title="Route missing CSRF protection",
                    context=f"{route.method} {route.uri}",
                    file=route.file_path or "routes/web.php",
                    line_start=route.line_number or 1,
                    description=(
                        f"Route `{route.method} {route.uri}` appears to be a state-changing route "
                        "without CSRF protection. This could allow Cross-Site Request Forgery attacks."
                    ),
                    why_it_matters=(
                        "Without CSRF protection:\n"
                        "- Attackers can trick users into submitting unwanted actions\n"
                        "- User accounts can be compromised\n"
                        "- Data can be modified without user consent\n"
                        "- OWASP Top 10 #8: Software and Data Integrity Failures"
                    ),
                    suggested_fix=(
                        "1. Add 'web' middleware group to the route:\n"
                        "   Route::middleware(['web'])->group(function () { ... });\n\n"
                        "2. Or add to routes/web.php (has web middleware by default)\n\n"
                        "3. For routes that need exemption:\n"
                        "   Route::post('webhook', [...])->withoutMiddleware([VerifyCsrfToken::class]);\n\n"
                        "4. Verify the route is in routes/web.php, not routes/api.php"
                    ),
                    code_example=(
                        "// routes/web.php - Has CSRF protection by default\n"
                        "Route::post('/profile/update', [ProfileController::class, 'update']);\n\n"
                        "// routes/api.php - No CSRF (uses token auth)\n"
                        "Route::post('/profile/update', [ProfileController::class, 'update'])\n"
                        "    ->middleware('auth:sanctum');\n\n"
                        "// Explicit CSRF exemption (use sparingly)\n"
                        "Route::post('/webhook/stripe', [WebhookController::class, 'stripe'])\n"
                        "    ->withoutMiddleware([VerifyCsrfToken::class]);"
                    ),
                    confidence=0.72 if is_in_web_routes else 0.80,
                    tags=["security", "csrf", "laravel", "owasp-a8"],
                    related_files=[route.file_path] if route.file_path else [],
                )
            )

        return findings

    def _discover_web_route_includes(self, facts: Facts) -> set[str]:
        root = Path(getattr(facts, "project_path", "") or ".")
        return self._collect_route_includes(root, "routes/web.php", set())

    def _collect_route_includes(self, root: Path, relative_path: str, seen: set[str]) -> set[str]:
        normalized = relative_path.replace("\\", "/").lower()
        if normalized in seen:
            return set()
        seen.add(normalized)

        file_path = root / normalized
        if not file_path.exists():
            return set()

        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return set()

        matches = set()
        patterns = [
            re.compile(r"base_path\(\s*['\"](?P<path>routes/[^'\"]+\.php)['\"]\s*\)", re.IGNORECASE),
            re.compile(r"__DIR__\s*\.\s*['\"]/+(?P<path>[^'\"]+\.php)['\"]", re.IGNORECASE),
        ]
        for pattern in patterns:
            for match in pattern.finditer(text):
                raw_path = (match.group("path") or "").replace("\\", "/").lstrip("./")
                if raw_path.startswith("routes/"):
                    child = raw_path.lower()
                elif raw_path.endswith(".php"):
                    child = f"routes/{raw_path.split('/')[-1]}".lower()
                else:
                    continue
                matches.add(child)
                matches.update(self._collect_route_includes(root, child, seen))
        return matches

    def _discover_csrf_exempt_patterns(self, facts: Facts) -> list[str]:
        root = Path(getattr(facts, "project_path", "") or ".")
        bootstrap_file = root / "bootstrap" / "app.php"
        if not bootstrap_file.exists():
            return []

        try:
            text = bootstrap_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        match = re.search(r"validateCsrfTokens\s*\(\s*except\s*:\s*\[(?P<body>.*?)\]\s*\)", text, re.IGNORECASE | re.DOTALL)
        if not match:
            return []
        body = match.group("body") or ""
        return [item.strip().strip("'\"").strip().lower().lstrip("/") for item in re.findall(r"['\"]([^'\"]+)['\"]", body)]

    def _matches_exempt_pattern(self, uri: str, patterns: list[str]) -> bool:
        for pattern in patterns:
            normalized = pattern.strip("/").lower()
            if not normalized:
                continue
            if normalized.endswith("*"):
                if uri.startswith(normalized[:-1]):
                    return True
            elif uri == normalized or uri.startswith(normalized + "/"):
                return True
        return False

    def _is_in_web_include_chain(self, route_file_path: str | None, web_route_includes: set[str]) -> bool:
        normalized = (route_file_path or "").replace("\\", "/").strip().lower()
        if not normalized:
            return False
        if normalized in web_route_includes:
            return True

        basename = normalized.split("/")[-1]
        route_relative = basename if basename.startswith("routes/") else f"routes/{basename}"
        if route_relative in web_route_includes:
            return True

        return any(
            normalized.endswith(f"/{included}") or normalized.endswith(f"\\{included}") or normalized.endswith(f"/{included.split('/')[-1]}")
            for included in web_route_includes
        )

    def _is_exempt_route(self, uri: str) -> bool:
        """Check if route matches exempt patterns."""
        for pattern in self._EXEMPT_ROUTE_PATTERNS:
            if pattern.endswith("/*"):
                prefix = pattern[:-2]
                if uri.startswith(prefix):
                    return True
            elif uri == pattern or uri.startswith(pattern + "/"):
                return True
        return False

    def _is_auth_scaffold_route(self, route: RouteInfo, uri: str, web_route_includes: set[str]) -> bool:
        uri_low = (uri or "").strip("/").lower()
        if not uri_low:
            return False
        if uri_low not in self._AUTH_ROUTE_HINTS and not any(
            uri_low.startswith(f"{hint}/") for hint in self._AUTH_ROUTE_HINTS
        ):
            return False

        middleware = {str(m).lower() for m in (route.middleware or [])}
        if not ({"auth", "guest"} & middleware):
            return False

        route_path = (route.file_path or "").replace("\\", "/").lower()
        if route_path.endswith("routes/auth.php") or "/routes/auth-" in route_path:
            return True

        if self._is_in_web_include_chain(route.file_path, web_route_includes):
            return True

        return False
