from core.ruleset import RuleConfig
from core.rule_engine import create_engine, ALL_RULES
from core.ruleset import Ruleset
from rules.php.unused_private_method import UnusedPrivateMethodRule
from rules.laravel.unused_service_class import UnusedServiceClassRule
from schemas.facts import Facts, ClassInfo, MethodInfo, ClassConstAccess


def test_unused_private_method_flags_only_unreferenced_private_methods():
    facts = Facts(project_path=".")

    facts.classes.append(
        ClassInfo(
            name="Foo",
            fqcn="App\\Services\\Foo",
            file_path="app/Services/Foo.php",
            file_hash="a",
            line_start=1,
            line_end=80,
        )
    )

    # Public entrypoint calls the helper.
    facts.methods.append(
        MethodInfo(
            name="run",
            class_name="Foo",
            class_fqcn="App\\Services\\Foo",
            file_path="app/Services/Foo.php",
            file_hash="a",
            visibility="public",
            line_start=10,
            line_end=20,
            loc=11,
            call_sites=["$this->usedHelper()"],
        )
    )

    facts.methods.append(
        MethodInfo(
            name="usedHelper",
            class_name="Foo",
            class_fqcn="App\\Services\\Foo",
            file_path="app/Services/Foo.php",
            file_hash="a",
            visibility="private",
            line_start=30,
            line_end=35,
            loc=6,
        )
    )

    facts.methods.append(
        MethodInfo(
            name="unusedHelper",
            class_name="Foo",
            class_fqcn="App\\Services\\Foo",
            file_path="app/Services/Foo.php",
            file_hash="a",
            visibility="private",
            line_start=40,
            line_end=45,
            loc=6,
        )
    )

    # Magic methods should never be flagged.
    facts.methods.append(
        MethodInfo(
            name="__construct",
            class_name="Foo",
            class_fqcn="App\\Services\\Foo",
            file_path="app/Services/Foo.php",
            file_hash="a",
            visibility="private",
            line_start=5,
            line_end=8,
            loc=4,
        )
    )

    rule = UnusedPrivateMethodRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings

    assert any(f.rule_id == "unused-private-method" and f.context.endswith("::unusedHelper") for f in findings)
    assert not any("::usedHelper" in f.context for f in findings)
    assert not any("__construct" in f.context for f in findings)


def test_unused_private_method_detects_calls_embedded_in_assignments_and_scoped_expressions():
    facts = Facts(project_path=".")

    facts.classes.append(
        ClassInfo(
            name="LmsGameService",
            fqcn="App\\Services\\Lms\\LmsGameService",
            file_path="app/Services/Lms/LmsGameService.php",
            file_hash="svc",
            line_start=1,
            line_end=180,
        )
    )

    facts.methods.append(
        MethodInfo(
            name="startCategory",
            class_name="LmsGameService",
            class_fqcn="App\\Services\\Lms\\LmsGameService",
            file_path="app/Services/Lms/LmsGameService.php",
            file_hash="svc",
            visibility="public",
            line_start=20,
            line_end=50,
            loc=31,
            call_sites=[
                "$category = $this->fetchCategory($config['categoryId']);",
                "$this->validateParticipantCount($participants);",
                "$seriesId = self::ensureActiveSeries();",
            ],
        )
    )

    for line, name in [(70, "fetchCategory"), (80, "validateParticipantCount"), (90, "ensureActiveSeries"), (100, "unusedHelper")]:
        facts.methods.append(
            MethodInfo(
                name=name,
                class_name="LmsGameService",
                class_fqcn="App\\Services\\Lms\\LmsGameService",
                file_path="app/Services/Lms/LmsGameService.php",
                file_hash="svc",
                visibility="private",
                line_start=line,
                line_end=line + 5,
                loc=6,
            )
        )

    findings = UnusedPrivateMethodRule(RuleConfig()).run(facts, project_type="laravel_blade").findings

    assert any(f.context.endswith("::unusedHelper") for f in findings)
    assert not any(f.context.endswith("::fetchCategory") for f in findings)
    assert not any(f.context.endswith("::validateParticipantCount") for f in findings)
    assert not any(f.context.endswith("::ensureActiveSeries") for f in findings)


def test_unused_service_class_is_not_flagged_when_referenced_via_type_hint():
    facts = Facts(project_path=".")

    facts.classes.append(
        ClassInfo(
            name="FooService",
            fqcn="App\\Services\\FooService",
            file_path="app/Services/FooService.php",
            file_hash="a",
            line_start=1,
            line_end=40,
        )
    )
    facts.classes.append(
        ClassInfo(
            name="UnusedService",
            fqcn="App\\Services\\UnusedService",
            file_path="app/Services/UnusedService.php",
            file_hash="b",
            line_start=1,
            line_end=40,
        )
    )

    facts.classes.append(
        ClassInfo(
            name="XController",
            fqcn="App\\Http\\Controllers\\XController",
            file_path="app/Http/Controllers/XController.php",
            file_hash="c",
            line_start=1,
            line_end=60,
        )
    )

    # DI type hint should count as a reference.
    facts.methods.append(
        MethodInfo(
            name="__construct",
            class_name="XController",
            class_fqcn="App\\Http\\Controllers\\XController",
            file_path="app/Http/Controllers/XController.php",
            file_hash="c",
            visibility="public",
            line_start=10,
            line_end=20,
            loc=11,
            parameters=["FooService $svc"],
        )
    )

    rule = UnusedServiceClassRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings

    assert any(f.rule_id == "unused-service-class" and f.context == "App\\Services\\UnusedService" for f in findings)
    assert not any(f.context == "App\\Services\\FooService" for f in findings)


def test_unused_service_class_is_not_flagged_when_referenced_via_class_const_access():
    facts = Facts(project_path=".")

    facts.classes.append(
        ClassInfo(
            name="BoundViaProviderOnly",
            fqcn="App\\Services\\BoundViaProviderOnly",
            file_path="app/Services/BoundViaProviderOnly.php",
            file_hash="a",
            line_start=1,
            line_end=40,
        )
    )
    facts.classes.append(
        ClassInfo(
            name="UnusedService",
            fqcn="App\\Services\\UnusedService",
            file_path="app/Services/UnusedService.php",
            file_hash="b",
            line_start=1,
            line_end=40,
        )
    )

    facts.classes.append(
        ClassInfo(
            name="BindingOnlyServiceProvider",
            fqcn="App\\Providers\\BindingOnlyServiceProvider",
            file_path="app/Providers/BindingOnlyServiceProvider.php",
            file_hash="c",
            line_start=1,
            line_end=80,
        )
    )

    # Container binding map uses `Service::class` outside method bodies (class constant/properties).
    facts.class_const_accesses.append(
        ClassConstAccess(
            file_path="app/Providers/BindingOnlyServiceProvider.php",
            line_number=10,
            expression="BoundViaProviderOnly::class",
        )
    )
    facts.class_const_accesses.append(
        ClassConstAccess(
            file_path="app/Providers/BindingOnlyServiceProvider.php",
            line_number=11,
            expression="BoundViaProviderOnlyInterface::class",
        )
    )

    rule = UnusedServiceClassRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings

    assert any(f.rule_id == "unused-service-class" and f.context == "App\\Services\\UnusedService" for f in findings)
    assert not any(f.context == "App\\Services\\BoundViaProviderOnly" for f in findings)


def test_unused_service_class_is_not_flagged_when_referenced_via_interface_type_hint():
    facts = Facts(project_path=".")

    facts.classes.extend(
        [
            ClassInfo(
                name="RoleAssignmentService",
                fqcn="App\\Services\\Game\\RoleAssignmentService",
                file_path="app/Services/Game/RoleAssignmentService.php",
                file_hash="svc",
                line_start=1,
                line_end=40,
                implements=["App\\Services\\Game\\Contracts\\RoleAssignmentServiceInterface"],
            ),
            ClassInfo(
                name="StartRoundAction",
                fqcn="App\\Actions\\Game\\StartRoundAction",
                file_path="app/Actions/Game/StartRoundAction.php",
                file_hash="action",
                line_start=1,
                line_end=40,
            ),
        ]
    )

    facts.methods.append(
        MethodInfo(
            name="__construct",
            class_name="StartRoundAction",
            class_fqcn="App\\Actions\\Game\\StartRoundAction",
            file_path="app/Actions/Game/StartRoundAction.php",
            file_hash="action",
            visibility="public",
            line_start=10,
            line_end=18,
            loc=9,
            parameters=["RoleAssignmentServiceInterface $roleAssignmentService"],
        )
    )

    findings = UnusedServiceClassRule(RuleConfig()).run(facts, project_type="laravel_blade").findings
    assert findings == []


def test_unused_service_class_survives_strict_confidence_filter():
    facts = Facts(project_path=".")
    facts.classes.append(
        ClassInfo(
            name="UnusedService",
            fqcn="App\\Services\\UnusedService",
            file_path="app/Services/UnusedService.php",
            file_hash="svc",
            line_start=1,
            line_end=40,
        )
    )

    rules = {rid: RuleConfig(enabled=False) for rid in ALL_RULES.keys()}
    rules["unused-service-class"] = RuleConfig(enabled=True)
    ruleset = Ruleset(rules=rules, name="strict")
    engine = create_engine(ruleset=ruleset, selected_rules=["unused-service-class"])
    result = engine.run(facts, project_type="laravel_blade")

    assert any(f.rule_id == "unused-service-class" and f.context == "App\\Services\\UnusedService" for f in result.findings)
