from core.ruleset import RuleConfig
from rules.php.god_class import GodClassRule
from schemas.facts import Facts, ClassInfo, MethodInfo


def test_god_class_does_not_mix_methods_across_same_class_name_different_namespaces():
    facts = Facts(project_path=".")

    # Two classes with the same short name but different namespaces/files.
    facts.classes.append(
        ClassInfo(
            name="UserService",
            fqcn="App\\Services\\UserService",
            file_path="app/Services/UserService.php",
            file_hash="a",
            line_start=1,
            line_end=120,
        )
    )
    facts.classes.append(
        ClassInfo(
            name="UserService",
            fqcn="Domain\\Users\\UserService",
            file_path="domain/Users/UserService.php",
            file_hash="b",
            line_start=1,
            line_end=120,
        )
    )

    # Each class has 2 public methods; if we mixed by class_name only, we'd count 4.
    for i in range(2):
        facts.methods.append(
            MethodInfo(
                name=f"m{i}",
                class_name="UserService",
                class_fqcn="App\\Services\\UserService",
                file_path="app/Services/UserService.php",
                file_hash="a",
                line_start=10 + i * 10,
                line_end=15 + i * 10,
                loc=6,
                visibility="public",
            )
        )
        facts.methods.append(
            MethodInfo(
                name=f"m{i}",
                class_name="UserService",
                class_fqcn="Domain\\Users\\UserService",
                file_path="domain/Users/UserService.php",
                file_hash="b",
                line_start=10 + i * 10,
                line_end=15 + i * 10,
                loc=6,
                visibility="public",
            )
        )

    rule = GodClassRule(RuleConfig(thresholds={"max_methods": 3, "max_loc": 500}))
    res = rule.run(facts, project_type="")

    # Neither class individually exceeds max_methods=3.
    assert not any(f.rule_id == "god-class" for f in res.findings)

