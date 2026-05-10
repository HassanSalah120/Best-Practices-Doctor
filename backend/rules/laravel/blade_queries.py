"""
Blade Queries Rule
Detects Eloquent queries in Blade templates (performance anti-pattern).
"""
from rules.base import Rule
from schemas.facts import BladeQuery, Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class BladeQueriesRule(Rule):
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Reduce the blade queries detection by moving expensive work out of hot paths or adding the missing cache/query optimization. Keep the behavior identical and cover the faster path with a focused test.'
    examples = {}
    priority = 3
    group = 'Performance'
    applies_to = ['blade']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'ast'
    analysis_cost = 'medium'
    auto_fixable = False
    tags = {'domain': 'laravel', 'type': 'performance', 'concern': 'blade-queries'}
    """
    Detects database queries in Blade templates.

    This is a serious performance anti-pattern because:
    - Queries in views are hard to optimize
    - N+1 problems are invisible
    - Cannot use eager loading properly
    - Views should only display data, not fetch it
    """

    id = "blade-queries"
    name = "Blade Queries Detection"
    description = "Detects database queries in Blade templates"
    category = Category.PERFORMANCE
    default_severity = Severity.HIGH
    applicable_project_types = [
        "laravel_blade",
        "laravel_livewire",
    ]

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings = []

        # Check detected blade queries
        for blade_query in facts.blade_queries:
            findings.append(self._create_finding(blade_query))

        return findings

    def _create_finding(self, blade_query: BladeQuery) -> Finding:
        """Create finding for Blade query."""
        return self.create_finding(
            title="Database query in Blade template",
            context=blade_query.query_snippet[:120],
            file=blade_query.file_path,
            line_start=blade_query.line_number,
            description=(
                f"Found database query in Blade template: `{blade_query.query_snippet[:50]}...`. "
                f"Views should display data, not fetch it."
            ),
            why_it_matters=(
                "Queries in Blade templates cause several problems:\n"
                "- N+1 queries: each iteration can trigger a new query\n"
                "- No eager loading: harder to optimize with `with()` / `load()`\n"
                "- Hard to debug: query logic hidden in the view layer\n"
                "- Poor separation: views should be presentation-only"
            ),
            suggested_fix=(
                "1. Move the query to your controller\n"
                "2. Use eager loading with `with()` for relationships\n"
                "3. Pass the data to the view via `compact()` or `->with()`\n"
                "4. In Blade, just iterate over the passed collection"
            ),
            code_example=self._generate_example(blade_query),
            tags=["performance", "n+1", "blade", "architecture"],
        )

    def _generate_example(self, blade_query: BladeQuery) -> str:
        """Generate before/after example."""
        return """// BEFORE (query in Blade) (avoid)
@foreach(App\\Models\\User::all() as $user)
    <li>{{ $user->name }} - {{ $user->posts->count() }} posts</li>
@endforeach

// AFTER (query in Controller)
// In Controller:
public function index()
{
    $users = User::with('posts')->get();
    return view('users.index', compact('users'));
}

// In Blade:
@foreach($users as $user)
    <li>{{ $user->name }} - {{ $user->posts->count() }} posts</li>
@endforeach"""
