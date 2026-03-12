"""
God Class Rule
Flags classes that are too large (many lines and/or many methods).
"""
from schemas.facts import Facts, ClassInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class GodClassRule(Rule):
    """
    Detects "god classes" (low cohesion, too many responsibilities).

    Heuristics:
    - Large LOC (class size)
    - Large public-ish method count
    """

    id = "god-class"
    name = "God Class Detection"
    description = "Flags classes that are too large and likely violate SRP/cohesion"
    category = Category.MAINTAINABILITY
    default_severity = Severity.HIGH

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        max_loc = self.get_threshold("max_loc", self.get_threshold("max_lines", 300))
        max_methods = self.get_threshold("max_methods", 20)

        for cls in facts.classes:
            # Skip framework/vendor classes that might slip through.
            if not cls.file_path or "vendor" in cls.file_path.replace("\\", "/"):
                continue

            loc = 0
            if cls.line_end and cls.line_start and cls.line_end >= cls.line_start:
                loc = cls.line_end - cls.line_start + 1

            methods = []
            for m in facts.methods:
                if m.name.startswith("__"):
                    continue
                # Prefer FQCN match when available to avoid mixing namespaces.
                if m.class_fqcn and cls.fqcn and m.class_fqcn == cls.fqcn:
                    methods.append(m)
                    continue
                # Fallback: file + class name match (still disambiguates duplicates across namespaces).
                if m.file_path == cls.file_path and m.class_name == cls.name:
                    methods.append(m)
            public_like = [m for m in methods if (m.visibility or "public") == "public"]

            # Trigger on either dimension; give richer description if both are exceeded.
            too_large = loc > max_loc if max_loc else False
            too_many = len(public_like) > max_methods if max_methods else False
            if not (too_large or too_many):
                continue

            reasons: list[str] = []
            if too_large:
                reasons.append(f"class is {loc} LOC (threshold: {max_loc})")
            if too_many:
                reasons.append(f"class has {len(public_like)} public methods (threshold: {max_methods})")

            findings.append(
                self.create_finding(
                    title="Class is too large (god class)",
                    context=cls.fqcn or cls.name,
                    file=cls.file_path,
                    line_start=cls.line_start or 1,
                    line_end=cls.line_end or None,
                    description=(
                        f"Class `{cls.name}` looks like a god class: " + ", ".join(reasons) + ". "
                        "This often indicates mixed responsibilities and low cohesion."
                    ),
                    why_it_matters=(
                        "God classes accumulate unrelated behavior, become difficult to test, and make changes risky. "
                        "Breaking them up improves cohesion, reduces coupling, and makes the codebase easier to evolve."
                    ),
                    suggested_fix=(
                        "1. Identify distinct responsibilities within the class\n"
                        "2. Extract cohesive behavior into smaller classes (Services, Actions, Value Objects)\n"
                        "3. Prefer composition over inheritance\n"
                        "4. Add tests around the extracted seams"
                    ),
                    tags=["srp", "cohesion", "maintainability", "refactor"],
                )
            )

        return findings
