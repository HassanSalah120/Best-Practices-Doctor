from analysis.facts_builder import FactsBuilder
from core.detector import ProjectDetector
from core.ruleset import RuleConfig
from rules.laravel.controller_business_logic import ControllerBusinessLogicRule
from rules.laravel.service_extraction import ServiceExtractionRule
from schemas.facts import ClassInfo, Facts, MethodInfo
from schemas.finding import Severity
from schemas.metrics import MethodMetrics


def test_business_context_detects_api_backend_for_api_first_fixture(fixture_path):
    fixture = fixture_path / "laravel-api-first-valid-mini"
    info = ProjectDetector(str(fixture)).detect()
    facts = FactsBuilder(info).build()

    assert facts.project_context.project_business_context == "api_backend"
    assert facts.project_context.project_business_confidence > 0.0
    assert facts.project_context.project_business_confidence_kind in {"structural", "heuristic"}
    assert facts.project_context.project_business_signals


def test_controller_business_logic_adds_project_aware_saas_guidance():
    facts = Facts(project_path=".")
    facts.project_context.backend_architecture_profile = "layered"
    facts.project_context.backend_profile_confidence = 0.91
    facts.project_context.backend_profile_confidence_kind = "structural"
    facts.project_context.project_business_context = "saas_platform"
    facts.project_context.backend_capabilities = {
        "billing": {"enabled": True, "confidence": 0.91, "source": "detected", "evidence": ["billing_services"]},
        "multi_tenant": {"enabled": True, "confidence": 0.87, "source": "detected", "evidence": ["tenant_scope"]},
    }

    controller = ClassInfo(
        name="BillingController",
        fqcn="App\\Http\\Controllers\\BillingController",
        file_path="app/Http/Controllers/BillingController.php",
        file_hash="ctrl",
        line_start=1,
        line_end=180,
    )
    method = MethodInfo(
        name="checkout",
        class_name=controller.name,
        class_fqcn=controller.fqcn,
        file_path=controller.file_path,
        file_hash="ctrl",
        line_start=40,
        line_end=130,
        loc=91,
        call_sites=[
            "$request->validated()",
            "$this->calculateCharge($request->amount)",
            "$this->applyDiscount($request->coupon)",
            "$this->syncPlan($account)",
            "return redirect()->route('billing.success')",
        ],
    )
    facts.controllers.append(controller)
    facts.methods.append(method)
    metrics = {
        method.method_fqn: MethodMetrics(
            method_fqn=method.method_fqn,
            file_path=method.file_path,
            cyclomatic_complexity=12,
            conditional_count=5,
            loop_count=1,
            query_count=1,
            validation_count=1,
            has_business_logic=True,
            business_logic_confidence=0.9,
        )
    }

    findings = ControllerBusinessLogicRule(RuleConfig()).analyze(facts, metrics)

    assert findings
    finding = findings[0]
    assert finding.severity == Severity.HIGH
    assert "Project-aware guidance" in finding.suggested_fix
    assert "subscription lifecycle" in finding.suggested_fix.lower()
    assert finding.metadata["decision_profile"]["project_business_context"] == "saas_platform"
    assert "billing" in finding.metadata["decision_profile"]["capabilities"]


def test_service_extraction_adds_project_aware_realtime_guidance():
    facts = Facts(project_path=".")
    facts.project_context.backend_architecture_profile = "layered"
    facts.project_context.project_business_context = "realtime_game_control_platform"
    facts.project_context.backend_capabilities = {
        "realtime": {"enabled": True, "confidence": 0.88, "source": "detected", "evidence": ["should_broadcast"]},
    }

    controller = ClassInfo(
        name="GameController",
        fqcn="App\\Http\\Controllers\\GameController",
        file_path="app/Http/Controllers/GameController.php",
        file_hash="ctrl",
        line_start=1,
        line_end=160,
    )
    method = MethodInfo(
        name="startRound",
        class_name=controller.name,
        class_fqcn=controller.fqcn,
        file_path=controller.file_path,
        file_hash="ctrl",
        line_start=25,
        line_end=96,
        loc=72,
        call_sites=[
            "$session = $this->sessionRepository->find($id)",
            "$phase = $this->computeRoundPhase($session)",
            "$this->dispatchRealtimeState($session, $phase)",
            "return response()->json(['ok' => true])",
        ],
    )
    facts.controllers.append(controller)
    facts.methods.append(method)
    metrics = {
        method.method_fqn: MethodMetrics(
            method_fqn=method.method_fqn,
            file_path=method.file_path,
            cyclomatic_complexity=9,
            conditional_count=4,
            has_business_logic=True,
            business_logic_confidence=0.82,
        )
    }

    findings = ServiceExtractionRule(RuleConfig()).analyze(facts, metrics)

    assert findings
    finding = findings[0]
    assert finding.severity == Severity.HIGH
    assert "Project-aware guidance" in finding.suggested_fix
    assert "event/state synchronization" in finding.suggested_fix.lower()
    assert finding.metadata["decision_profile"]["project_business_context"] == "realtime_game_control_platform"
