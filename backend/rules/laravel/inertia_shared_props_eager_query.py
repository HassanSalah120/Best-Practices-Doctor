"""
Inertia Shared Props Eager Query Rule

Detects database queries executed eagerly in global Inertia shared props.
"""

from __future__ import annotations

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class InertiaSharedPropsEagerQueryRule(Rule):
    id = "inertia-shared-props-eager-query"
    name = "Inertia Shared Props Eager Query"
    description = "Detects eager database queries inside global Inertia shared props"
    category = Category.PERFORMANCE
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types = ["laravel_inertia_react", "laravel_inertia_vue"]
    regex_file_extensions = [".php"]

    _PATH_HINTS = ("handleinertiarequests.php", "/middleware/", "/providers/")
    _FILE_HINTS = ("inertia::share", "function share(", "parent::share(")
    _QUERY_TOKENS = (
        "::all(",
        "::count(",
        "::latest(",
        "::oldest(",
        "::paginate(",
        "::simplepaginate(",
        "::cursorpaginate(",
        "::query()->count(",
        "::query()->get(",
        "::query()->first(",
        "::query()->paginate(",
        "db::table(",
        "db::query(",
        "db::select(",
    )

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
        norm = (file_path or "").replace("\\", "/").lower()
        text = content or ""
        low = text.lower()
        if not any(hint in norm for hint in self._PATH_HINTS) and not any(hint in low for hint in self._FILE_HINTS):
            return []

        for line_no, line in enumerate(text.splitlines(), start=1):
            line_low = line.lower()
            if "=>" not in line_low:
                continue
            if "fn" in line_low or "function" in line_low:
                continue
            if not any(token in line_low for token in self._QUERY_TOKENS):
                continue
            return [
                self.create_finding(
                    title="Inertia shared props run an eager query on every request",
                    context=f"{file_path}:{line_no}:share",
                    file=file_path,
                    line_start=line_no,
                    description=(
                        "Detected a database query executed directly in global Inertia shared props instead of "
                        "behind a lazy closure."
                    ),
                    why_it_matters=(
                        "Global shared props run on every Inertia response. Eager queries there add hidden latency "
                        "and can degrade the entire app."
                    ),
                    suggested_fix=(
                        "Wrap expensive shared props in lazy closures such as `fn () => Order::count()` and avoid "
                        "sharing large query results globally when the page does not always need them."
                    ),
                    tags=["laravel", "inertia", "performance", "shared-props"],
                    confidence=0.82,
                    evidence_signals=["shared_props_eager_query=true", f"line={line_no}"],
                )
            ]
        return []
