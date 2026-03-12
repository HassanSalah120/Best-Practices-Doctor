"""
Env Usage Rule
Flags direct `env()` calls outside Laravel config files.
"""
from schemas.facts import Facts, EnvUsage
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class EnvOutsideConfigRule(Rule):
    """
    In Laravel, `env()` should generally only be used in `config/*.php`.
    Application code should use `config()` so values participate in config caching.
    """

    id = "env-outside-config"
    name = "Avoid env() Outside Config"
    description = "Detects direct env() usage outside config files"
    category = Category.LARAVEL_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for usage in facts.env_usages:
            findings.append(self._create_finding(usage))

        return findings

    def _create_finding(self, usage: EnvUsage) -> Finding:
        return self.create_finding(
            title="Avoid using env() outside config files",
            file=usage.file_path,
            line_start=usage.line_number,
            description=(
                "Direct `env()` usage was detected outside `config/*.php`. "
                "This can behave unexpectedly when config caching is enabled."
            ),
            why_it_matters=(
                "`php artisan config:cache` loads environment variables into config at build time. "
                "If application code calls `env()` directly, values may differ between environments or be unavailable."
            ),
            suggested_fix=(
                "1. Move the env lookup into a config file (e.g. `config/services.php`)\n"
                "2. Read it via `config('services.foo.bar')` in application code\n"
                "3. Ensure `config:cache` works in deployment"
            ),
            code_example=(
                "// config/services.php\n"
                "return [\n"
                "    'stripe' => [\n"
                "        'key' => env('STRIPE_KEY'),\n"
                "    ],\n"
                "];\n\n"
                "// app code\n"
                "$key = config('services.stripe.key');\n"
            ),
            context=usage.snippet or "",
            tags=["laravel", "config", "env", "deployment"],
        )

