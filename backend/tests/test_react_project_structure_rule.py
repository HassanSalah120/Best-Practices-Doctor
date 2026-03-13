from core.rule_engine import ALL_RULES, RuleEngine
from core.ruleset import RuleConfig, Ruleset
from rules.react.project_structure_consistency import ReactProjectStructureConsistencyRule
from schemas.facts import Facts, ReactComponentInfo


def test_react_project_structure_accepts_consistent_category_based_layout():
    rule = ReactProjectStructureConsistencyRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.files = [
        "src/hooks/auth/useAuth.ts",
        "src/hooks/appointment/useAppointment.ts",
        "src/services/auth/authService.ts",
        "src/services/appointment/appointmentService.ts",
        "src/utils/shared/dateUtil.ts",
        "src/helpers/shared/currencyHelper.ts",
        "src/types/auth/session.types.ts",
        "src/constants/auth/roles.ts",
        "src/pages/auth/Login.tsx",
        "src/pages/appointment/Book.tsx",
    ]

    findings = rule.run(facts).findings
    assert findings == []


def test_react_project_structure_flags_mixed_chaotic_layout():
    rule = ReactProjectStructureConsistencyRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.files = [
        "src/hooks/useAuth.ts",
        "src/features/appointment/useAppointment.ts",
        "src/pages/patients/services/patientService.ts",
        "src/lib/dateUtil.ts",
        "src/usePatients.ts",
        "src/appointmentService.ts",
        "src/shared/types/user.types.ts",
        "src/pages/auth/Login.tsx",
    ]

    findings = rule.run(facts).findings

    assert findings
    assert any(f.metadata.get("inferred_pattern") == "mixed-chaotic" for f in findings)
    assert any("inconsistent-placement" in f.tags for f in findings)


def test_react_project_structure_flags_shared_logic_buried_in_feature_folder():
    rule = ReactProjectStructureConsistencyRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.files = [
        "src/features/auth/hooks/useSession.ts",
        "src/features/auth/Login.tsx",
        "src/features/appointments/Book.tsx",
        "src/features/profile/Profile.tsx",
    ]
    facts._frontend_symbol_graph = {
        "files": {
            "src/features/auth/Login.tsx": {"imports": ["./hooks/useSession"]},
            "src/features/appointments/Book.tsx": {"imports": ["../auth/hooks/useSession"]},
            "src/features/profile/Profile.tsx": {"imports": ["../auth/hooks/useSession"]},
        }
    }

    findings = rule.run(facts).findings

    assert any("buried inside feature folders" in f.title for f in findings)
    assert any(f.file == "src/features/auth/hooks/useSession.ts" for f in findings)


def test_react_project_structure_accepts_intentional_colocated_utils_with_shared_utils():
    rule = ReactProjectStructureConsistencyRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.files = [
        "resources/js/pages/Patients/Create.tsx",
        "resources/js/pages/Patients/Create.utils.ts",
        "resources/js/layouts/PatientPortalLayout.tsx",
        "resources/js/layouts/PatientPortalLayout.utils.ts",
        "resources/js/utils/scheduleUtils.ts",
        "resources/js/hooks/useAuth.ts",
        "resources/js/services/patients/patientService.ts",
        "resources/js/types/patients/patient.types.ts",
    ]

    findings = rule.run(facts).findings
    assert findings == []


def test_react_project_structure_skips_global_utils_used_by_single_domain_when_intentional():
    rule = ReactProjectStructureConsistencyRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.files = [
        "resources/js/layouts/PatientPortalLayout.tsx",
        "resources/js/layouts/PatientPortalLayout.utils.ts",
        "resources/js/pages/Patients/Create.tsx",
        "resources/js/pages/Patients/Create.utils.ts",
        "resources/js/pages/Patients/Index.tsx",
        "resources/js/utils/scheduleUtils.ts",
        "resources/js/hooks/useAuth.ts",
        "resources/js/services/patients/patientService.ts",
        "resources/js/types/patients/patient.types.ts",
    ]
    facts._frontend_symbol_graph = {
        "files": {
            "resources/js/pages/Patients/Create.tsx": {"imports": ["./Create.utils", "@/utils/scheduleUtils"]},
            "resources/js/pages/Patients/Index.tsx": {"imports": ["@/utils/scheduleUtils"]},
            "resources/js/layouts/PatientPortalLayout.tsx": {"imports": ["./PatientPortalLayout.utils"]},
        }
    }

    findings = rule.run(facts).findings
    assert findings == []


def test_react_project_structure_accepts_shared_top_level_hooks_in_feature_project():
    rule = ReactProjectStructureConsistencyRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.files = [
        "resources/js/hooks/useEmailBooking.ts",
        "resources/js/layouts/PatientPortalLayout.tsx",
        "resources/js/layouts/PatientPortalLayout.utils.ts",
        "resources/js/pages/Patients/Create.tsx",
        "resources/js/pages/Patients/Create.utils.ts",
        "resources/js/pages/Bookings/Index.tsx",
    ]
    facts._frontend_symbol_graph = {
        "files": {
            "resources/js/pages/Bookings/Index.tsx": {"imports": ["@/hooks/useEmailBooking"]},
            "resources/js/pages/Patients/Create.tsx": {"imports": ["./Create.utils"]},
            "resources/js/layouts/PatientPortalLayout.tsx": {"imports": ["./PatientPortalLayout.utils"]},
        }
    }

    findings = rule.run(facts).findings
    assert findings == []


def test_react_project_structure_accepts_shared_hook_and_component_types_in_hybrid_project():
    rule = ReactProjectStructureConsistencyRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.files = [
        "resources/js/components/UI/Button.tsx",
        "resources/js/components/UI/Button.types.ts",
        "resources/js/hooks/useInsuranceCarrierFilters.ts",
        "resources/js/pages/Clinic/Insurance/Carriers/Index.tsx",
        "resources/js/pages/Clinic/Settings/Index.tsx",
    ]
    facts.project_context.react_structure_mode = "hybrid"
    facts.project_context.react_shared_roots = ["hooks", "components"]
    facts._frontend_symbol_graph = {
        "files": {
            "resources/js/components/UI/Button.tsx": {"imports": ["./Button.types"]},
            "resources/js/pages/Clinic/Insurance/Carriers/Index.tsx": {"imports": ["@/hooks/useInsuranceCarrierFilters", "@/components/UI/Button"]},
        }
    }

    findings = rule.run(facts).findings
    assert findings == []


def test_rule_engine_runs_facts_based_react_rules():
    rules = {rule_id: RuleConfig(enabled=False) for rule_id in ALL_RULES.keys()}
    rules["large-react-component"] = RuleConfig(enabled=True)
    engine = RuleEngine(Ruleset(rules=rules))

    facts = Facts(project_path=".")
    facts.react_components.append(
        ReactComponentInfo(
            name="BigPage",
            file_path="src/pages/BigPage.tsx",
            file_hash="deadbeef",
            line_start=1,
            line_end=320,
            loc=320,
        )
    )

    findings = engine.run(facts, project_type="laravel_inertia_react").findings
    assert any(f.rule_id == "large-react-component" for f in findings)


def test_rule_engine_runs_supplemental_regex_for_analyze_based_react_rules(tmp_path):
    root = tmp_path / "proj"
    page = root / "src" / "pages" / "FormPage.tsx"
    page.parent.mkdir(parents=True, exist_ok=True)
    page.write_text(
        """
export function FormPage() {
  return <div>{persistPatientDraft('alice')}</div>;
}

function persistPatientDraft(name) {
  return name.trim().toUpperCase();
}
""",
        encoding="utf-8",
    )

    rules = {rule_id: RuleConfig(enabled=False) for rule_id in ALL_RULES.keys()}
    rules["no-inline-services"] = RuleConfig(enabled=True)
    engine = RuleEngine(Ruleset(rules=rules))

    facts = Facts(project_path=str(root))
    facts.files = ["src/pages/FormPage.tsx"]

    findings = engine.run(facts, project_type="laravel_inertia_react").findings
    assert any(f.rule_id == "no-inline-services" for f in findings)
