"""
Controller Inheritance Inconsistency Rule

Detects projects where some controllers extend a shared base class while others
extend the raw Laravel `Controller` class. Mixed inheritance patterns suggest
inconsistent application of shared controller infrastructure (helpers, tenant
context resolution, response formatting).

ADVISORY — some projects intentionally mix inheritance. Low confidence.
"""

from __future__ import annotations

from collections import defaultdict

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


class ControllerInheritanceInconsistencyRule(Rule):
    id = "controller-inheritance-inconsistency"
    name = "Controller Inheritance Inconsistency"
    description = "Detects mixed controller inheritance patterns (some extend BaseController, others extend Controller)"
    category = Category.ARCHITECTURE
    default_severity = Severity.LOW
    default_classification = FindingClassification.ADVISORY
    type = "ast"
    severity_weight = 2
    confidence = "low"
    fix_suggestion = (
        "Extend a shared base controller to inherit common infrastructure:\n"
        "```php\n"
        "class PatientController extends BaseController\n"
        "{\n"
        "    // ...\n"
        "}\n"
        "```\n"
        "This ensures consistent tenant resolution, response formatting, and "
        "authorization helpers across all controllers."
    )
    examples = {}
    priority = 3
    group = "Architecture Integrity"
    applies_to = ["controller"]
    references = []
    related_rules = ["fat-controller", "controller-business-logic"]
    false_positive_notes = (
        "Some controllers intentionally extend raw Controller (e.g., health checks, "
        "webhooks, public pages) where base controller overhead is unnecessary. "
        "Review each flagged controller before refactoring."
    )
    detection_type = "ast"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "architecture", "concern": "inheritance"}

    _EXCLUDED_NAMES = {"controller", "basecontroller"}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        controllers = getattr(facts, "controllers", []) or []
        if len(controllers) < 5:
            return []

        bases: defaultdict[str, list[str]] = defaultdict(list)
        total = 0
        for ctrl in controllers:
            extends = str(ctrl.extends or "").strip()
            if not extends:
                continue
            low_ext = extends.lower().replace("\\", "").replace("/", "")
            if low_ext in self._EXCLUDED_NAMES:
                bases["Controller (Laravel)"].append(ctrl.name or "unknown")
            else:
                bases[extends].append(ctrl.name or "unknown")
            total += 1

        if len(bases) < 2:
            return []

        sorted_bases = sorted(bases.items(), key=lambda x: -len(x[1]))
        primary_base, primary_count = sorted_bases[0]
        secondary_groups = [(name, ctls) for name, ctls in sorted_bases[1:] if len(ctls) >= 1]

        if not secondary_groups:
            return []

        minority_total = sum(len(ctls) for _, ctls in secondary_groups)
        minority_ratio = minority_total / total if total > 0 else 0
        if minority_ratio > 0.45:
            return []

        group_lines = []
        for base_name, ctls in secondary_groups:
            ctl_list = ", ".join(ctls[:5])
            suffix = f" and {len(ctls) - 5} more" if len(ctls) > 5 else ""
            group_lines.append(f"  - {len(ctls)} extend {base_name}: {ctl_list}{suffix}")

        return [
            self.create_finding(
                title="Mixed controller inheritance detected",
                context=f"{len(bases)} different base classes across {total} controllers",
                file=controllers[0].file_path,
                line_start=1,
                description=(
                    f"Of {total} controllers, {primary_count} extend {primary_base}, "
                    f"but {minority_total} extend different base classes:\n"
                    + "\n".join(group_lines)
                ),
                why_it_matters=(
                    "Mixed inheritance means some controllers miss shared infrastructure "
                    "(tenant context, response helpers, error handling) provided by the "
                    "primary base class, leading to inconsistent behavior."
                ),
                suggested_fix=self.fix_suggestion,
                confidence=0.65,
                tags=["laravel", "architecture", "consistency"],
                evidence_signals=[
                    f"total_controllers={total}",
                    f"primary_base={primary_base}({primary_count})",
                    f"minority_count={minority_total}",
                ],
            ),
        ]
