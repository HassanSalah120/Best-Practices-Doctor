"""
Inertia Hybrid Controller Rule

Detects controller files containing both Inertia::render() and Blade view() calls.
This indicates an incomplete migration to Inertia or architectural confusion.
Controllers should use one rendering strategy consistently.
"""

from __future__ import annotations

import re

from rules.laravel._inertia_helpers import is_inertia_project
from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class InertiaHybridControllerRule(Rule):
    id = "inertia-hybrid-controller"
    name = "Inertia Hybrid Controller"
    description = "Detects controllers mixing Inertia::render() and Blade view() calls"
    category = Category.ARCHITECTURE
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types = ["laravel_inertia_react", "laravel_inertia_vue"]
    regex_file_extensions = [".php"]

    _INERTIA_RENDER = re.compile(r"Inertia::render\s*\(", re.IGNORECASE)
    _BLADE_VIEW = re.compile(
        r"(?:return\s+)?(?:view\s*\(|View::make\s*\()",
        re.IGNORECASE,
    )
    _ABSTRACT_CLASS = re.compile(
        r"abstract\s+class\s+\w+",
        re.IGNORECASE,
    )

    _ALLOWLIST_PATHS = (
        "tests/",
        "/tests/",
        "test/",
        "/test/",
        "vendor/",
        "/vendor/",
        "routes/",
        "config/",
        "database/",
        "providers/",
        "/providers/",
    )

    _ADMIN_PATHS = (
        "admin/",
        "/admin/",
        "backend/",
        "/backend/",
        "panel/",
        "/panel/",
    )

    severity_weight = 0
    confidence = "high"
    fix_suggestion = (
        "Choose one rendering strategy per controller. "
        "If migrating to Inertia, replace view() calls with Inertia::render(). "
        "If the admin panel uses Blade while the main app uses Inertia, "
        "move Blade-rendering methods to a separate Admin controller."
    )
    examples = {
        "bad": (
            "class UserController extends Controller\n"
            "{\n"
            "    public function index()\n"
            "    {\n"
            "        return Inertia::render('Users/Index', ['users' => User::all()]);\n"
            "    }\n\n"
            "    public function export()\n"
            "    {\n"
            "        return view('users.export', ['users' => User::all()]);\n"
            "    }\n"
            "}"
        ),
        "good": (
            "// All methods use Inertia::render()\n"
            "class UserController extends Controller\n"
            "{\n"
            "    public function index()\n"
            "    {\n"
            "        return Inertia::render('Users/Index', ['users' => User::all()]);\n"
            "    }\n\n"
            "    public function export()\n"
            "    {\n"
            "        return Inertia::render('Users/Export', ['users' => User::all()]);\n"
            "    }\n"
            "}"
        ),
    }
    priority = 2
    group = "Architecture Integrity"
    applies_to = ["controller"]
    references = []
    related_rules = [
        "inertia-route-returns-json-response",
        "inertia-api-route-returns-inertia",
        "controller-returning-view-in-api",
    ]
    false_positive_notes = (
        "May fire on base/abstract controllers or admin panels that intentionally mix "
        "rendering strategies. Abstract classes and admin/panel directories are excluded."
    )
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "architecture", "concern": "inertia-hybrid-rendering"}

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
        findings: list[Finding] = []

        if not is_inertia_project(facts, file_path):
            return findings

        norm_path = (file_path or "").replace("\\", "/").lower()
        if any(allow in norm_path for allow in self._ALLOWLIST_PATHS):
            return findings

        if any(admin in norm_path for admin in self._ADMIN_PATHS):
            return findings

        text = content or ""
        if not text.strip():
            return findings

        if self._ABSTRACT_CLASS.search(text):
            return findings

        has_inertia = self._INERTIA_RENDER.search(text) is not None
        has_blade = self._BLADE_VIEW.search(text) is not None

        if not (has_inertia and has_blade):
            return findings

        blade_match = self._BLADE_VIEW.search(text)
        line = text.count("\n", 0, blade_match.start()) + 1

        return [
            self.create_finding(
                title="Controller mixes Inertia::render() and Blade view() calls",
                context=text[:80].strip(),
                file=file_path,
                line_start=line,
                description=(
                    "This controller contains both Inertia::render() and Blade view() "
                    "calls, indicating an incomplete migration or architectural confusion."
                ),
                why_it_matters=(
                    "Mixing rendering strategies in one controller:\n"
                    "- Makes the controller's responsibility unclear\n"
                    "- Suggests incomplete Inertia migration\n"
                    "- Increases cognitive load for developers\n"
                    "- Can lead to inconsistent UX between pages\n"
                    "- Makes testing harder (two rendering pipelines)"
                ),
                suggested_fix=self.fix_suggestion,
                confidence=0.90,
                tags=["laravel", "inertia", "architecture"],
            ),
        ]
