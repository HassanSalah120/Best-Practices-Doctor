from core.ruleset import RuleConfig
from rules.laravel.ioc_instead_of_new import IocInsteadOfNewRule
from schemas.facts import Facts, ClassInfo, MethodInfo


def _controller_class(name: str, file_path: str = "app/Http/Controllers/A.php") -> ClassInfo:
    return ClassInfo(
        name=name,
        fqcn=f"App\\Http\\Controllers\\{name}",
        file_path=file_path,
        file_hash="deadbeef",
        line_start=1,
        line_end=200,
    )


def _controller_method(
    class_name: str,
    method_name: str,
    instantiations: list[str],
    file_path: str = "app/Http/Controllers/A.php",
) -> MethodInfo:
    return MethodInfo(
        name=method_name,
        class_name=class_name,
        class_fqcn=f"App\\Http\\Controllers\\{class_name}",
        file_path=file_path,
        file_hash="deadbeef",
        line_start=10,
        line_end=60,
        loc=51,
        instantiations=instantiations,
    )


def test_ioc_rule_ignores_controller_dto_and_view_model_instantiations():
    facts = Facts(project_path=".")
    facts.controllers.append(_controller_class("AppointmentController"))
    facts.methods.append(
        _controller_method(
            "AppointmentController",
            "store",
            [
                "UpdateDoctorScheduleDTO",
                "\\App\\DTOs\\Partials\\DateRangeDTO",
                "ClinicBrandingViewDTO",
            ],
        )
    )

    rule = IocInsteadOfNewRule(RuleConfig())
    res = rule.run(facts, project_type="laravel_inertia_react")

    assert not res.findings


def test_ioc_rule_ignores_event_instantiation_and_flags_service_instantiation():
    facts = Facts(project_path=".")
    facts.controllers.append(_controller_class("RegisteredUserController"))
    facts.methods.append(
        _controller_method(
            "RegisteredUserController",
            "store",
            ["Registered", "App\\Services\\UserService"],
        )
    )

    rule = IocInsteadOfNewRule(RuleConfig())
    res = rule.run(facts, project_type="laravel_api")

    assert len(res.findings) == 1
    assert "App\\Services\\UserService" in res.findings[0].description
    assert "directly: Registered" not in res.findings[0].description


def test_ioc_rule_flags_repository_like_instantiation():
    facts = Facts(project_path=".")
    facts.controllers.append(_controller_class("OrdersController"))
    facts.methods.append(
        _controller_method(
            "OrdersController",
            "index",
            ["OrderRepository", "OrdersFiltersDTO"],
        )
    )

    rule = IocInsteadOfNewRule(RuleConfig())
    res = rule.run(facts, project_type="laravel_blade")

    assert len(res.findings) == 1
    assert "OrderRepository" in res.findings[0].description
    assert "OrdersFiltersDTO" not in res.findings[0].description
