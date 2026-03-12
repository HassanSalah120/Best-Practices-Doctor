"""
Missing CSRF Token Verification Rule

Detects routes that should have CSRF protection but don't.
"""

from __future__ import annotations

import re

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
        "email/*",         # Email verification
        "sanctum/*",       # Sanctum API
        "broadcasting/*",  # Broadcasting auth
    }

    # Middleware that indicates CSRF protection
    _CSRF_MIDDLEWARE = {"web", "verified", "auth"}

    # Middleware that explicitly disables CSRF
    _CSRF_EXEMPT_MIDDLEWARE = {"throttle", "api"}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Group routes by URI for analysis
        web_routes = [r for r in facts.routes if r.method.upper() in self._MUTATING_METHODS]

        for route in web_routes:
            # Skip exempt routes
            uri_lower = (route.uri or "").lower().strip("/")
            if self._is_exempt_route(uri_lower):
                continue

            # Check middleware
            middleware = [m.lower() for m in route.middleware or []]

            # API routes don't need CSRF (they use token auth)
            if "api" in middleware:
                continue

            # Check if route has web middleware (includes CSRF)
            has_web_middleware = "web" in middleware

            # Check if route explicitly excludes CSRF
            has_csrf_exempt = any(
                "csrf" in m and ("except" in m or "exclude" in m)
                for m in middleware
            )

            # If it's a web route without CSRF protection
            if not has_web_middleware and not has_csrf_exempt:
                # Check if it's a state-changing route in web context
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
                        confidence=0.80,
                        tags=["security", "csrf", "laravel", "owasp-a8"],
                        related_files=[route.file_path] if route.file_path else [],
                    )
                )

        return findings

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
