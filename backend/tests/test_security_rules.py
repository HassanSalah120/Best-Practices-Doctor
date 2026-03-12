from core.ruleset import RuleConfig
from rules.php.unsafe_eval import UnsafeEvalRule
from rules.php.unsafe_unserialize import UnsafeUnserializeRule
from rules.php.command_injection_risk import CommandInjectionRiskRule
from rules.php.sql_injection_risk import SqlInjectionRiskRule
from rules.laravel.blade_xss_risk import BladeXssRiskRule
from schemas.facts import Facts, MethodInfo, BladeRawEcho


def test_unsafe_eval_flags_eval_assert_string_and_preg_replace_e():
    facts = Facts(project_path=".")

    facts.methods.append(
        MethodInfo(
            name="run",
            class_name="C",
            class_fqcn="App\\C",
            file_path="app/C.php",
            file_hash="a",
            visibility="public",
            line_start=1,
            line_end=50,
            loc=50,
            call_sites=[
                "eval($code)",
                "assert('phpinfo();')",
                "preg_replace('/.*/e', 'x', $y)",
            ],
        )
    )
    facts.methods.append(
        MethodInfo(
            name="ok",
            class_name="C",
            class_fqcn="App\\C",
            file_path="app/C.php",
            file_hash="a",
            visibility="public",
            line_start=60,
            line_end=70,
            loc=11,
            call_sites=["assert($x === 1)"],
        )
    )

    rule = UnsafeEvalRule(RuleConfig())
    findings = rule.run(facts, project_type="").findings

    assert len(findings) == 1
    assert findings[0].rule_id == "unsafe-eval"
    assert findings[0].context == "App\\C::run"


def test_unsafe_unserialize_flags_without_allowed_classes_and_skips_safe_usage():
    facts = Facts(project_path=".")

    facts.methods.append(
        MethodInfo(
            name="bad",
            class_name="C",
            class_fqcn="App\\C",
            file_path="app/C.php",
            file_hash="a",
            visibility="public",
            line_start=1,
            line_end=20,
            loc=20,
            call_sites=["unserialize($request->input('p'))"],
        )
    )
    facts.methods.append(
        MethodInfo(
            name="good",
            class_name="C",
            class_fqcn="App\\C",
            file_path="app/C.php",
            file_hash="a",
            visibility="public",
            line_start=30,
            line_end=40,
            loc=11,
            call_sites=["unserialize($payload, ['allowed_classes' => false])"],
        )
    )

    rule = UnsafeUnserializeRule(RuleConfig())
    findings = rule.run(facts, project_type="").findings

    assert len(findings) == 1
    assert findings[0].rule_id == "unsafe-unserialize"
    assert findings[0].context == "App\\C::bad"


def test_command_injection_risk_flags_non_literal_and_skips_literal():
    facts = Facts(project_path=".")

    facts.methods.append(
        MethodInfo(
            name="bad",
            class_name="C",
            class_fqcn="App\\C",
            file_path="app/C.php",
            file_hash="a",
            visibility="public",
            line_start=1,
            line_end=20,
            loc=20,
            call_sites=["exec($cmd)"],
        )
    )
    facts.methods.append(
        MethodInfo(
            name="good",
            class_name="C",
            class_fqcn="App\\C",
            file_path="app/C.php",
            file_hash="a",
            visibility="public",
            line_start=30,
            line_end=40,
            loc=11,
            call_sites=["exec('ls')"],
        )
    )

    rule = CommandInjectionRiskRule(RuleConfig())
    findings = rule.run(facts, project_type="").findings

    assert len(findings) == 1
    assert findings[0].rule_id == "command-injection-risk"
    assert findings[0].context == "App\\C::bad"


def test_sql_injection_risk_flags_interpolated_sql_and_skips_parameterized_bindings():
    facts = Facts(project_path=".")

    facts.methods.append(
        MethodInfo(
            name="bad",
            class_name="C",
            class_fqcn="App\\C",
            file_path="app/C.php",
            file_hash="a",
            visibility="public",
            line_start=1,
            line_end=30,
            loc=30,
            call_sites=[
                'DB::select("select * from users where id = $id")',
                'User::whereRaw("id = $id")',
            ],
        )
    )
    facts.methods.append(
        MethodInfo(
            name="good",
            class_name="C",
            class_fqcn="App\\C",
            file_path="app/C.php",
            file_hash="a",
            visibility="public",
            line_start=40,
            line_end=60,
            loc=21,
            call_sites=[
                "DB::select('select * from users where id = ?', [$id])",
                "User::whereRaw('id = ?', [$id])",
                'DB::select("select 1")',
            ],
        )
    )

    rule = SqlInjectionRiskRule(RuleConfig())
    findings = rule.run(facts, project_type="").findings

    assert len(findings) == 1
    assert findings[0].rule_id == "sql-injection-risk"
    assert findings[0].context == "App\\C::bad"


def test_blade_xss_risk_flags_only_request_sourced_raw_echoes():
    facts = Facts(project_path=".")

    facts.blade_raw_echos.append(
        BladeRawEcho(
            file_path="resources/views/x.blade.php",
            line_number=10,
            expression="request('q')",
            is_request_source=True,
            snippet="{!! request('q') !!}",
        )
    )
    facts.blade_raw_echos.append(
        BladeRawEcho(
            file_path="resources/views/x.blade.php",
            line_number=20,
            expression="$user->name",
            is_request_source=False,
            snippet="{!! $user->name !!}",
        )
    )

    rule = BladeXssRiskRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings

    assert len(findings) == 1
    assert findings[0].rule_id == "blade-xss-risk"

