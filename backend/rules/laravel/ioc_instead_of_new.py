"""
IoC Instead Of `new` Rule
Suggests dependency injection instead of instantiating services in controllers.
"""
from __future__ import annotations

from schemas.facts import Facts, MethodInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class IocInsteadOfNewRule(Rule):
    """
    Flags `new SomeService()` usage in controllers.

    In Laravel, prefer injecting dependencies (constructor/method injection) so:
    - code is testable/mocked
    - dependencies are explicit
    - you can swap implementations via bindings
    """

    id = "ioc-instead-of-new"
    name = "Prefer IoC Over new"
    description = "Suggests injecting dependencies instead of instantiating them in controllers"
    category = Category.ARCHITECTURE
    default_severity = Severity.MEDIUM
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    _ALLOWLIST = {
        "DateTime",
        "DateTimeImmutable",
        "Exception",
        "RuntimeException",
        "InvalidArgumentException",
    }
    _VALUE_OBJECT_SUFFIXES = (
        "dto",
        "viewdto",
        "viewmodel",
        "data",
        "valueobject",
        "vo",
        "payload",
        "filter",
        "filters",
        "criteria",
        "requestdata",
    )
    _VALUE_OBJECT_NAMESPACE_MARKERS = (
        "\\dto\\",
        "\\dtos\\",
        "\\data\\",
        "\\viewmodel\\",
        "\\viewmodels\\",
        "\\valueobject\\",
        "\\valueobjects\\",
        "\\events\\",
        "\\enums\\",
    )
    _SERVICE_SUFFIXES = (
        "service",
        "repository",
        "manager",
        "client",
        "gateway",
        "adapter",
        "facade",
    )
    _SERVICE_NAMESPACE_MARKERS = (
        "\\service\\",
        "\\services\\",
        "\\repository\\",
        "\\repositories\\",
        "\\client\\",
        "\\clients\\",
        "\\gateway\\",
        "\\gateways\\",
    )

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        max_news = int(self.get_threshold("max_instantiations", 0) or 0)

        controller_names = {c.name for c in facts.controllers}

        for method in facts.methods:
            if method.class_name not in controller_names:
                continue
            if method.name.startswith("__"):
                continue

            inst = self._filter_ioc_candidates(method.instantiations or [])
            if not inst:
                continue
            if len(inst) <= max_news:
                continue

            findings.append(self._create_finding(method, inst))

        return findings

    def _filter_ioc_candidates(self, instantiations: list[str]) -> list[str]:
        result: list[str] = []
        seen: set[str] = set()
        for raw in instantiations:
            normalized = self._normalize_class_name(raw)
            if not normalized:
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            if not self._is_ioc_candidate(normalized):
                continue
            result.append(normalized)
        return result

    def _is_ioc_candidate(self, class_name: str) -> bool:
        short = self._short_class_name(class_name)
        short_lower = short.lower()
        full_lower = class_name.lower()

        if short in self._ALLOWLIST:
            return False

        if any(marker in full_lower for marker in self._VALUE_OBJECT_NAMESPACE_MARKERS):
            return False
        if any(short_lower.endswith(suffix) for suffix in self._VALUE_OBJECT_SUFFIXES):
            return False

        if any(marker in full_lower for marker in self._SERVICE_NAMESPACE_MARKERS):
            return True
        if any(short_lower.endswith(suffix) for suffix in self._SERVICE_SUFFIXES):
            return True

        return False

    @staticmethod
    def _normalize_class_name(class_name: str) -> str:
        s = str(class_name or "").strip()
        if not s:
            return ""
        while s.startswith("\\"):
            s = s[1:]
        s = s.replace("/", "\\")
        return s

    @staticmethod
    def _short_class_name(class_name: str) -> str:
        s = str(class_name or "")
        if "\\" in s:
            return s.split("\\")[-1]
        return s

    def _create_finding(self, method: MethodInfo, instantiations: list[str]) -> Finding:
        inst_list = ", ".join(instantiations[:5]) + ("..." if len(instantiations) > 5 else "")

        return self.create_finding(
            title="Prefer dependency injection over `new` in controllers",
            context=method.method_fqn,
            file=method.file_path,
            line_start=method.line_start,
            line_end=method.line_end,
            description=(
                f"Method `{method.method_fqn}` instantiates service-like dependencies directly: "
                f"{inst_list}. In controllers, this usually indicates hidden dependencies."
            ),
            why_it_matters=(
                "Direct instantiation makes code harder to test and refactor. "
                "Dependency injection (via Laravel's IoC container) keeps dependencies explicit "
                "and enables swapping implementations."
            ),
            suggested_fix=(
                "1. Move object creation to the container (bind interface to implementation)\n"
                "2. Inject the dependency via constructor or method injection\n"
                "3. Use interfaces for services/repositories when appropriate"
            ),
            code_example=(
                "// Before\n"
                "public function store(Request $request)\n"
                "{\n"
                "    $svc = new UserService();\n"
                "    return $svc->create($request->all());\n"
                "}\n\n"
                "// After (method injection)\n"
                "public function store(Request $request, UserService $svc)\n"
                "{\n"
                "    return $svc->create($request->all());\n"
                "}\n"
            ),
            tags=["laravel", "ioc", "di", "testing"],
        )
