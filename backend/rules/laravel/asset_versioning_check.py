"""
Asset Versioning Check Rule

Verifies that Inertia asset versioning is properly configured.
"""

from __future__ import annotations

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class AssetVersioningCheckRule(Rule):
    id = "asset-versioning-check"
    name = "Asset Versioning Check"
    description = "Verifies that Inertia asset versioning is properly configured"
    category = Category.PERFORMANCE
    default_severity = Severity.LOW
    applicable_project_types = [
        "laravel_inertia_react",
        "laravel_inertia_vue",
    ]

    _INERTIA_MIDDLEWARE = "HandleInertiaRequests"

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Find HandleInertiaRequests middleware
        inertia_middleware = None
        for c in facts.middleware:
            if self._INERTIA_MIDDLEWARE in (c.name or ""):
                inertia_middleware = c
                break

        if not inertia_middleware:
            # No Inertia middleware found - skip
            return findings

        # Check if version() method exists
        has_version_method = False
        for m in facts.methods:
            if m.class_name == self._INERTIA_MIDDLEWARE and m.name == "version":
                has_version_method = True
                break

        if not has_version_method:
            findings.append(
                self.create_finding(
                    title="Missing asset versioning in Inertia middleware",
                    context="HandleInertiaRequests::version()",
                    file=inertia_middleware.file_path,
                    line_start=inertia_middleware.line_start,
                    description=(
                        "The HandleInertiaRequests middleware does not implement the `version()` method. "
                        "Asset versioning ensures browsers fetch fresh assets after deployments."
                    ),
                    why_it_matters=(
                        "Without asset versioning:\n"
                        "- Browsers may cache stale JavaScript/CSS\n"
                        "- Users see broken UI after deployments\n"
                        "- Cache invalidation relies on file renaming\n"
                        "- May cause JavaScript errors with old API responses"
                    ),
                    suggested_fix=(
                        "1. Add version() method to HandleInertiaRequests:\n"
                        "   public function version(Request $request): ?string\n"
                        "   {\n"
                        "       if (app()->environment('testing', 'local')) {\n"
                        "           return null; // Hot reload support\n"
                        "       }\n"
                        "       return parent::version($request);\n"
                        "   }\n\n"
                        "2. This uses the mix manifest hash for versioning\n\n"
                        "3. In production, assets get a unique version hash\n\n"
                        "4. In development, null allows hot module replacement"
                    ),
                    code_example=(
                        "// app/Http/Middleware/HandleInertiaRequests.php\n\n"
                        "class HandleInertiaRequests extends Middleware\n"
                        "{\n"
                        "    // ... other methods ...\n\n"
                        "    public function version(Request $request): ?string\n"
                        "    {\n"
                        "        // Disable versioning in local/testing for hot reload\n"
                        "        if (app()->environment('testing', 'local')) {\n"
                        "            return null;\n"
                        "        }\n\n"
                        "        // Use manifest hash in production\n"
                        "        return parent::version($request);\n"
                        "    }\n"
                        "}"
                    ),
                    confidence=0.70,
                    tags=["performance", "inertia", "caching", "assets"],
                )
            )

        return findings
