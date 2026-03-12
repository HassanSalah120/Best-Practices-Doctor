from core.ruleset import RuleConfig
from rules.php.circular_dependency import CircularDependencyRule
from rules.php.high_coupling_class import HighCouplingClassRule
from schemas.facts import Facts, ClassInfo, MethodInfo


def test_circular_dependency_detects_cycle_in_app_namespace():
    facts = Facts(project_path=".")

    # Two App services with constructor DI cycle.
    facts.classes.append(
        ClassInfo(
            name="A",
            fqcn="App\\Services\\A",
            file_path="app/Services/A.php",
            file_hash="a",
            line_start=1,
            line_end=30,
        )
    )
    facts.classes.append(
        ClassInfo(
            name="B",
            fqcn="App\\Services\\B",
            file_path="app/Services/B.php",
            file_hash="b",
            line_start=1,
            line_end=30,
        )
    )

    facts.methods.append(
        MethodInfo(
            name="__construct",
            class_name="A",
            class_fqcn="App\\Services\\A",
            file_path="app/Services/A.php",
            file_hash="a",
            visibility="public",
            line_start=5,
            line_end=10,
            loc=6,
            parameters=["\\App\\Services\\B $b"],
        )
    )
    facts.methods.append(
        MethodInfo(
            name="__construct",
            class_name="B",
            class_fqcn="App\\Services\\B",
            file_path="app/Services/B.php",
            file_hash="b",
            visibility="public",
            line_start=5,
            line_end=10,
            loc=6,
            parameters=["\\App\\Services\\A $a"],
        )
    )

    rule = CircularDependencyRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings

    assert any(f.rule_id == "circular-dependency" for f in findings)
    f0 = next(f for f in findings if f.rule_id == "circular-dependency")
    # Evidence list should contain the cycle members.
    assert "App\\Services\\A" in (f0.related_methods or [])
    assert "App\\Services\\B" in (f0.related_methods or [])


def test_circular_dependency_no_findings_when_acyclic():
    facts = Facts(project_path=".")
    facts.classes.append(
        ClassInfo(
            name="A",
            fqcn="App\\Services\\A",
            file_path="app/Services/A.php",
            file_hash="a",
            line_start=1,
            line_end=30,
        )
    )
    facts.classes.append(
        ClassInfo(
            name="B",
            fqcn="App\\Services\\B",
            file_path="app/Services/B.php",
            file_hash="b",
            line_start=1,
            line_end=30,
        )
    )

    facts.methods.append(
        MethodInfo(
            name="__construct",
            class_name="A",
            class_fqcn="App\\Services\\A",
            file_path="app/Services/A.php",
            file_hash="a",
            visibility="public",
            line_start=5,
            line_end=10,
            loc=6,
            parameters=["\\App\\Services\\B $b"],
        )
    )

    rule = CircularDependencyRule(RuleConfig())
    assert not rule.run(facts, project_type="laravel_blade").findings


def test_circular_dependency_skips_standard_bidirectional_eloquent_relationships():
    facts = Facts(project_path=".")
    facts.classes.append(
        ClassInfo(
            name="EmailCampaign",
            fqcn="App\\Models\\EmailCampaign",
            file_path="app/Models/EmailCampaign.php",
            file_hash="email",
            line_start=1,
            line_end=30,
        )
    )
    facts.classes.append(
        ClassInfo(
            name="CampaignRecipient",
            fqcn="App\\Models\\CampaignRecipient",
            file_path="app/Models/CampaignRecipient.php",
            file_hash="recipient",
            line_start=1,
            line_end=30,
        )
    )

    facts.methods.append(
        MethodInfo(
            name="recipients",
            class_name="EmailCampaign",
            class_fqcn="App\\Models\\EmailCampaign",
            file_path="app/Models/EmailCampaign.php",
            file_hash="email",
            visibility="public",
            line_start=10,
            line_end=13,
            loc=4,
            call_sites=["return $this->hasMany(CampaignRecipient::class, 'campaign_id');"],
        )
    )
    facts.methods.append(
        MethodInfo(
            name="campaign",
            class_name="CampaignRecipient",
            class_fqcn="App\\Models\\CampaignRecipient",
            file_path="app/Models/CampaignRecipient.php",
            file_hash="recipient",
            visibility="public",
            line_start=10,
            line_end=13,
            loc=4,
            call_sites=["return $this->belongsTo(EmailCampaign::class, 'campaign_id');"],
        )
    )

    rule = CircularDependencyRule(RuleConfig())
    assert not rule.run(facts, project_type="laravel_blade").findings


def test_high_coupling_class_flags_when_outgoing_dependencies_exceed_threshold():
    facts = Facts(project_path=".")

    facts.classes.append(
        ClassInfo(
            name="Coupled",
            fqcn="App\\Services\\Coupled",
            file_path="app/Services/Coupled.php",
            file_hash="c",
            line_start=1,
            line_end=40,
        )
    )
    # Dependencies (App namespace)
    for i in range(5):
        facts.classes.append(
            ClassInfo(
                name=f"D{i}",
                fqcn=f"App\\Services\\D{i}",
                file_path=f"app/Services/D{i}.php",
                file_hash=str(i),
                line_start=1,
                line_end=10,
            )
        )

    facts.methods.append(
        MethodInfo(
            name="build",
            class_name="Coupled",
            class_fqcn="App\\Services\\Coupled",
            file_path="app/Services/Coupled.php",
            file_hash="c",
            visibility="public",
            line_start=10,
            line_end=20,
            loc=11,
            instantiations=[f"\\App\\Services\\D{i}" for i in range(5)],
        )
    )

    rule = HighCouplingClassRule(RuleConfig(thresholds={"max_outgoing": 3}))
    findings = rule.run(facts, project_type="laravel_blade").findings
    assert any(f.rule_id == "high-coupling-class" and f.context == "App\\Services\\Coupled" for f in findings)


def test_high_coupling_class_no_findings_under_threshold():
    facts = Facts(project_path=".")
    facts.classes.append(
        ClassInfo(
            name="Small",
            fqcn="App\\Services\\Small",
            file_path="app/Services/Small.php",
            file_hash="s",
            line_start=1,
            line_end=10,
        )
    )
    facts.classes.append(
        ClassInfo(
            name="D0",
            fqcn="App\\Services\\D0",
            file_path="app/Services/D0.php",
            file_hash="d",
            line_start=1,
            line_end=10,
        )
    )
    facts.methods.append(
        MethodInfo(
            name="build",
            class_name="Small",
            class_fqcn="App\\Services\\Small",
            file_path="app/Services/Small.php",
            file_hash="s",
            visibility="public",
            line_start=2,
            line_end=4,
            loc=3,
            instantiations=["\\App\\Services\\D0"],
        )
    )

    rule = HighCouplingClassRule(RuleConfig(thresholds={"max_outgoing": 3}))
    assert not rule.run(facts, project_type="laravel_blade").findings
