"""
Config In Loop Rule

Detects `config()` calls inside loops (performance smell).
Uses ConfigUsage facts extracted from AST (Tree-sitter primary).
"""
from rules.base import Rule
from schemas.facts import ConfigUsage, Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class ConfigInLoopRule(Rule):
    id = "config-in-loop"
    name = "config() Call Inside Loop"
    description = "Detects config() calls inside loops (cache value outside the loop)"
    category = Category.PERFORMANCE
    default_severity = Severity.MEDIUM
    applicable_project_types: list[str] = []  # all
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Reduce the config() call inside loop by moving expensive work out of hot paths or adding the missing cache/query optimization. Keep the behavior identical and cover the faster path with a focused test.'
    examples = {}
    priority = 3
    group = 'Performance'
    applies_to = ['php-class']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'ast'
    analysis_cost = 'medium'
    auto_fixable = False
    tags = {'domain': 'php', 'type': 'performance', 'concern': 'config-in-loop'}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        max_calls = int(self.get_threshold("max_calls", 0))

        grouped: dict[tuple[str, str], list[ConfigUsage]] = {}
        for cu in facts.config_usages:
            if not cu.in_loop:
                continue
            grouped.setdefault((cu.file_path, cu.method_name), []).append(cu)

        for (file_path, method_name), xs in grouped.items():
            if len(xs) <= max_calls:
                continue

            line_start = min(x.line_number for x in xs)
            ctx = f"{file_path}:{method_name}:config_in_loop"

            sample = xs[0].snippet or "config(...)"
            findings.append(
                self.create_finding(
                    title="Avoid config() inside loops",
                    context=ctx,
                    file=file_path,
                    line_start=line_start,
                    description=(
                        f"Detected {len(xs)} `config()` call(s) inside a loop. Example: `{sample}`. "
                        "Move the config lookup outside the loop."
                    ),
                    why_it_matters=(
                        "Calling `config()` repeatedly in tight loops adds overhead and obscures intent. "
                        "Caching the value once improves performance and readability."
                    ),
                    suggested_fix=(
                        "1. Read config once before the loop: `$x = config('...');`\n"
                        "2. Use `$x` inside the loop\n"
                        "3. For frequently used values, consider injecting config or using a typed config object"
                    ),
                    tags=["performance", "config", "loops"],
                    confidence=0.7,
                ),
            )

        return findings

