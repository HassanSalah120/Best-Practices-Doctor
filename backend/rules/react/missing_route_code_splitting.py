"""Missing route code splitting rule."""
from __future__ import annotations

import re
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule

class MissingRouteCodeSplittingRule(Rule):
    id = "missing-route-code-splitting"
    name = "Missing Route Code Splitting"
    description = "Detects router files with many static page imports instead of React.lazy"
    category = Category.PERFORMANCE
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]
    severity_weight = 8
    confidence = "medium"
    fix_suggestion = "Wrap route-level components in React.lazy() and Suspense. This splits the bundle so users only download what they need."
    examples = {"bad": "import Dashboard from './pages/Dashboard';", "good": "const Dashboard = React.lazy(() => import('./pages/Dashboard'));"}
    priority = 2
    group = "React Performance"
    applies_to = ["page", "route"]
    references = []
    related_rules = []
    false_positive_notes = "Inertia projects are skipped because Inertia has a separate page resolution/code-splitting path."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "react", "type": "performance", "concern": "bundles"}
    _IMPORT = re.compile(r"^import\s+\w+\s+from\s+['\"].*(?:pages|routes|screens)/", re.MULTILINE)
    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]: return []
    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        norm=file_path.replace('\\','/').lower()
        if not any(part in norm for part in ['router', 'routes']): return []
        if '@inertiajs' in content or 'resolvePageComponent' in content or 'React.lazy' in content: return []
        imports=list(self._IMPORT.finditer(content))
        if len(imports) < 5: return []
        line=content.count('\n',0,imports[0].start())+1
        return [self.create_finding("Route components are statically imported", file_path, line, "This router imports many route/page components synchronously.", "Static route imports push more JavaScript into the initial bundle than users need for their first screen.", self.fix_suggestion, context=file_path, confidence=0.7, tags=["react", "performance", "bundle"])]
