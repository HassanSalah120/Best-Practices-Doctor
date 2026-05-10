"""
Eager Loading Rule
Detects potential N+1 issues and suggests eager loading.
"""
from rules.base import Rule
from schemas.facts import Facts, QueryUsage
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class EagerLoadingRule(Rule):
    severity_weight = 0
    confidence = 'low'
    fix_suggestion = 'Reduce the eager loading suggestion by moving expensive work out of hot paths or adding the missing cache/query optimization. Keep the behavior identical and cover the faster path with a focused test.'
    examples = {}
    priority = 4
    group = 'Performance'
    applies_to = ['global']
    references = []
    related_rules = []
    false_positive_notes = 'This is a heuristic/style signal and may be acceptable when the team has an explicit convention for this pattern.'
    detection_type = 'ast'
    analysis_cost = 'medium'
    auto_fixable = False
    tags = {'domain': 'laravel', 'type': 'performance', 'concern': 'eager-loading'}
    """
    Flags queries that appear in loop contexts without eager loading.

    This is heuristic-based; confidence is lowered when we can't infer a relationship access,
    but a query inside a loop is still a strong signal.
    """

    id = "eager-loading"
    name = "Eager Loading Suggestion"
    description = "Suggests eager loading to prevent N+1 query problems"
    category = Category.PERFORMANCE
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

        for q in facts.queries:
            if q.has_eager_loading:
                continue
            if (q.n_plus_one_risk or "none") == "none":
                continue
            # Skip non-SELECT queries (INSERT, UPDATE, DELETE) - N+1 only applies to SELECT
            if q.query_type != "select":
                continue

            findings.append(self._create_finding(q))

        return findings

    def _create_finding(self, q: QueryUsage) -> Finding:
        model = q.model or "Model"
        chain = q.method_chain or "query"
        confidence = 0.7 if q.n_plus_one_risk == "high" else 0.5

        return self.create_finding(
            title="Potential N+1 query: add eager loading",
            context=f"{q.method_name}:{model}:{chain}",
            file=q.file_path,
            line_start=q.line_number,
            description=(
                f"Detected a query in a loop context without eager loading. "
                f"Model: `{model}`, chain: `{chain}`."
            ),
            why_it_matters=(
                "N+1 queries can turn a single page load into dozens or hundreds of database round-trips. "
                "Eager loading (`with()` / `load()`) fetches related data efficiently."
            ),
            suggested_fix=(
                "1. Move queries out of loops\n"
                "2. Use eager loading: `Model::with('relation')->...->get()`\n"
                "3. Inspect queries with Laravel Debugbar/Telescope to confirm\n"
                "4. Add tests or performance assertions for hot endpoints"
            ),
            code_example=(
                "// Before\n"
                "@foreach ($users as $user)\n"
                "    {{ $user->posts->count() }}\n"
                "@endforeach\n\n"
                "// After (Controller)\n"
                "$users = User::with('posts')->get();\n"
            ),
            confidence=confidence,
            tags=["performance", "n+1", "eloquent", "eager-loading"],
        )

