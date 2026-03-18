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

    _COORDINATOR_NAME_MARKERS = (
        "coordinator",
        "orchestrator",
        "workflow",
        "server",
        "manager",
        "handler",
        "gateway",
        "dispatcher",
        "broker",
        "router",
    )
    _SERVICE_PARAM_MARKERS = (
        "service",
        "handler",
        "manager",
        "gateway",
        "dispatcher",
        "broker",
        "publisher",
        "interface",
        "queue",
        "token",
        "command",
        "connection",
        "circuitbreaker",
        "visibility",
        "repository",
        "validator",
        "transport",
        "store",
    )

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
        project_context = getattr(facts, "project_context", None)
        architecture_profile = str(getattr(project_context, "backend_architecture_profile", "unknown") or "unknown").lower()
        if architecture_profile == "unknown":
            architecture_profile = "layered" if str(getattr(project_context, "backend_structure_mode", "unknown") or "unknown").lower() == "layered" else "unknown"
        profile_confidence = float(getattr(project_context, "backend_profile_confidence", 0.0) or 0.0)
        profile_confidence_kind = str(getattr(project_context, "backend_profile_confidence_kind", "unknown") or "unknown")
        profile_signals = list(getattr(project_context, "backend_profile_signals", []) or [])

        for cls in facts.classes:
            # Skip framework/vendor classes that might slip through.
            if not cls.file_path or "vendor" in cls.file_path.replace("\\", "/"):
                continue

            loc = 0
            if cls.line_end and cls.line_start and cls.line_end >= cls.line_start:
                loc = cls.line_end - cls.line_start + 1

            methods = []
            all_class_methods = []
            for m in facts.methods:
                # Prefer FQCN match when available to avoid mixing namespaces.
                if m.class_fqcn and cls.fqcn and m.class_fqcn == cls.fqcn:
                    all_class_methods.append(m)
                    if m.name.startswith("__"):
                        continue
                    methods.append(m)
                    continue
                # Fallback: file + class name match (still disambiguates duplicates across namespaces).
                if m.file_path == cls.file_path and m.class_name == cls.name:
                    all_class_methods.append(m)
                    if m.name.startswith("__"):
                        continue
                    methods.append(m)
            public_like = [m for m in methods if (m.visibility or "public") == "public"]

            # Trigger on either dimension; give richer description if both are exceeded.
            too_large = loc > max_loc if max_loc else False
            too_many = len(public_like) > max_methods if max_methods else False
            if not (too_large or too_many):
                continue

            coordinator_shape = self._is_service_coordinator(cls, public_like, all_class_methods, architecture_profile)
            if too_large and not too_many and coordinator_shape:
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
                    confidence=min(0.95, 0.62 + (0.14 if too_large else 0.0) + (0.14 if too_many else 0.0)),
                    evidence_signals=[
                        f"profile={architecture_profile}",
                        f"profile_confidence={profile_confidence:.2f}",
                        f"profile_confidence_kind={profile_confidence_kind}",
                        f"loc={loc}",
                        f"public_methods={len(public_like)}",
                        f"coordinator_shape={int(coordinator_shape)}",
                    ],
                    metadata={
                        "decision_profile": {
                            "backend_framework": "laravel" if architecture_profile != "unknown" else "unknown",
                            "architecture_profile": architecture_profile,
                            "profile_confidence": round(profile_confidence, 2),
                            "profile_confidence_kind": profile_confidence_kind,
                            "profile_signals": profile_signals[:8],
                            "loc": loc,
                            "public_methods": len(public_like),
                            "coordinator_shape": coordinator_shape,
                            "too_large": too_large,
                            "too_many_methods": too_many,
                            "decision": "emit",
                            "decision_summary": "emit because class exceeds size thresholds without bounded coordinator suppression",
                        }
                    },
                )
            )

        return findings

    def _is_service_coordinator(self, cls: ClassInfo, public_like: list, methods: list, architecture_profile: str) -> bool:
        path = str(cls.file_path or "").replace("\\", "/").lower()
        name = str(cls.name or "").lower()
        layered_like = architecture_profile in {"layered", "modular"}
        has_coordinator_name = any(marker in name for marker in self._COORDINATOR_NAME_MARKERS)
        has_coordinator_path = any(marker in path for marker in ("/workflow/", "/workflows/", "/coordination/", "/orchestrators/", "/servers/"))
        has_layered_server = layered_like and "/services/" in path and "server" in name
        if not (has_coordinator_name or has_coordinator_path or has_layered_server):
            return False

        constructor = next((m for m in methods if m.name == "__construct"), None)
        if constructor is None:
            return False

        params = [str(param or "").lower() for param in (constructor.parameters or [])]
        if len(params) < 5:
            return False

        service_like = sum(
            1 for param in params if any(marker in param for marker in self._SERVICE_PARAM_MARKERS)
        )
        if service_like < max(4, len(params) - 1):
            return False

        if architecture_profile == "mvc" and not any(marker in name for marker in ("coordinator", "orchestrator", "workflow")):
            return False

        if len(public_like) > (16 if layered_like else 14):
            return False

        avg_public_loc = (
            sum((m.loc or max(0, (m.line_end or 0) - (m.line_start or 0) + 1)) for m in public_like) / len(public_like)
            if public_like else 0
        )
        return avg_public_loc <= (55 if layered_like else 45)
