from core.ruleset import RuleConfig
from schemas.facts import Facts, RelationAccess, ClassInfo, MethodInfo, QueryUsage
from rules.laravel.n_plus_one_risk import NPlusOneRiskRule


def test_n_plus_one_ignores_dto_iteration_access():
    facts = Facts(project_path="x")
    facts.relation_accesses = [
        RelationAccess(
            file_path="app/Repositories/TreatmentPlanRepository.php",
            line_number=42,
            method_name="buildTimeline",
            class_fqcn="App\\Repositories\\TreatmentPlanRepository",
            base_var="$stageDto",
            relation="procedures",
            loop_kind="collection_flatMap",
            access_type="property",
        )
    ]

    rule = NPlusOneRiskRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings
    assert findings == []


def test_n_plus_one_ignores_scalar_model_columns_in_loops():
    facts = Facts(project_path="x")
    facts.relation_accesses = [
        RelationAccess(
            file_path="app/Services/AppointmentCalendarService.php",
            line_number=30,
            method_name="buildAbsenceSlots",
            class_fqcn="App\\Services\\AppointmentCalendarService",
            base_var="$absence",
            relation="start_date",
            loop_kind="foreach",
            access_type="property",
        ),
        RelationAccess(
            file_path="app/Services/AppointmentIndexService.php",
            line_number=65,
            method_name="index",
            class_fqcn="App\\Services\\AppointmentIndexService",
            base_var="$absence",
            relation="reason",
            loop_kind="foreach",
            access_type="property",
        ),
    ]

    rule = NPlusOneRiskRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings
    assert findings == []


def test_n_plus_one_ignores_enum_value_iteration():
    facts = Facts(project_path="x")
    facts.relation_accesses = [
        RelationAccess(
            file_path="app/Services/AppointmentIndexService.php",
            line_number=91,
            method_name="filters",
            class_fqcn="App\\Services\\AppointmentIndexService",
            base_var="$status",
            relation="value",
            loop_kind="collection_map",
            access_type="property",
        )
    ]

    rule = NPlusOneRiskRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings
    assert findings == []


def test_n_plus_one_still_flags_real_relation_access():
    facts = Facts(project_path="x")
    facts.classes = [
        ClassInfo(
            name="User",
            fqcn="App\\Models\\User",
            file_path="app/Models/User.php",
            file_hash="h1",
        )
    ]
    facts.methods = [
        MethodInfo(
            name="posts",
            class_name="User",
            class_fqcn="App\\Models\\User",
            file_path="app/Models/User.php",
            file_hash="h1",
            call_sites=["$this->hasMany(Post::class)"],
        )
    ]
    facts.queries = [
        QueryUsage(
            file_path="app/Http/Controllers/UserController.php",
            line_number=18,
            method_name="index",
            model="User",
            method_chain="all",
            has_eager_loading=False,
            n_plus_one_risk="high",
        )
    ]
    facts.relation_accesses = [
        RelationAccess(
            file_path="app/Http/Controllers/UserController.php",
            line_number=22,
            method_name="index",
            class_fqcn="App\\Http\\Controllers\\UserController",
            base_var="$user",
            relation="posts",
            loop_kind="foreach",
            access_type="property",
        )
    ]

    rule = NPlusOneRiskRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings
    assert any(f.rule_id == "n-plus-one-risk" for f in findings)


def test_n_plus_one_ignores_collection_mapper_without_query_context():
    facts = Facts(project_path="x")
    facts.relation_accesses = [
        RelationAccess(
            file_path="app/Services/Mappers/AppointmentTimelineMapper.php",
            line_number=20,
            method_name="map",
            class_fqcn="App\\Services\\Mappers\\AppointmentTimelineMapper",
            base_var="$appointment",
            relation="doctor",
            loop_kind="collection_map",
            access_type="property",
        )
    ]

    rule = NPlusOneRiskRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings
    assert findings == []


def test_n_plus_one_ignores_known_model_non_relation_property_even_with_query():
    facts = Facts(project_path="x")
    facts.classes = [
        ClassInfo(
            name="Appointment",
            fqcn="App\\Models\\Appointment",
            file_path="app/Models/Appointment.php",
            file_hash="h2",
        )
    ]
    facts.methods = [
        MethodInfo(
            name="doctor",
            class_name="Appointment",
            class_fqcn="App\\Models\\Appointment",
            file_path="app/Models/Appointment.php",
            file_hash="h2",
            call_sites=["$this->belongsTo(User::class)"],
        )
    ]
    facts.queries = [
        QueryUsage(
            file_path="app/Services/X.php",
            line_number=10,
            method_name="run",
            model="Appointment",
            method_chain="where->get",
            has_eager_loading=False,
            n_plus_one_risk="high",
        )
    ]
    facts.relation_accesses = [
        RelationAccess(
            file_path="app/Services/X.php",
            line_number=14,
            method_name="run",
            class_fqcn="App\\Services\\X",
            base_var="$appointment",
            relation="notes",
            loop_kind="foreach",
            access_type="property",
        )
    ]

    rule = NPlusOneRiskRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings
    assert findings == []


def test_n_plus_one_uses_query_model_context_for_generic_loop_variable():
    facts = Facts(project_path="x")
    facts.classes = [
        ClassInfo(
            name="InventoryItem",
            fqcn="App\\Models\\InventoryItem",
            file_path="app/Models/InventoryItem.php",
            file_hash="h3",
        )
    ]
    facts.methods = [
        MethodInfo(
            name="batches",
            class_name="InventoryItem",
            class_fqcn="App\\Models\\InventoryItem",
            file_path="app/Models/InventoryItem.php",
            file_hash="h3",
            call_sites=["$this->hasMany(InventoryBatch::class)"],
        )
    ]
    facts.queries = [
        QueryUsage(
            file_path="app/Services/InventoryService.php",
            line_number=20,
            method_name="getItemsForClinic",
            model="InventoryItem",
            method_chain="where->get",
            has_eager_loading=False,
            n_plus_one_risk="high",
        )
    ]
    facts.relation_accesses = [
        RelationAccess(
            file_path="app/Services/InventoryService.php",
            line_number=29,
            method_name="getItemsForClinic",
            class_fqcn="App\\Services\\InventoryService",
            base_var="$item",
            relation="category",  # scalar field, not declared relation on InventoryItem
            loop_kind="collection_map",
            access_type="property",
        )
    ]

    rule = NPlusOneRiskRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings
    assert findings == []


def test_n_plus_one_ignores_eager_loaded_relations_with_nested():
    """Test that nested eager-loaded relations like ->with(['patient.clinic']) are not flagged."""
    facts = Facts(project_path="x")
    facts.classes = [
        ClassInfo(
            name="Appointment",
            fqcn="App\\Models\\Appointment",
            file_path="app/Models/Appointment.php",
            file_hash="h1",
        ),
        ClassInfo(
            name="Patient",
            fqcn="App\\Models\\Patient",
            file_path="app/Models/Patient.php",
            file_hash="h2",
        ),
    ]
    facts.methods = [
        MethodInfo(
            name="patient",
            class_name="Appointment",
            class_fqcn="App\\Models\\Appointment",
            file_path="app/Models/Appointment.php",
            file_hash="h1",
            call_sites=["$this->belongsTo(Patient::class)"],
        ),
    ]
    facts.queries = [
        QueryUsage(
            file_path="app/Services/SurveyService.php",
            line_number=126,
            method_name="processSurveys",
            model="Appointment",
            method_chain="with->where->get",
            has_eager_loading=True,
            n_plus_one_risk="none",
        ),
    ]
    facts.relation_accesses = [
        # Accessing patient relation that was eager loaded
        RelationAccess(
            file_path="app/Services/SurveyService.php",
            line_number=128,
            method_name="processSurveys",
            class_fqcn="App\\Services\\SurveyService",
            base_var="$appointment",
            relation="patient",
            loop_kind="foreach",
            access_type="property",
        ),
    ]

    rule = NPlusOneRiskRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings
    assert findings == [], f"Expected no findings for eager-loaded relations, got: {findings}"


def test_n_plus_one_ignores_layered_service_loop_backed_by_repository_boundary():
    facts = Facts(project_path="x")
    facts.project_context.backend_architecture_profile = "layered"
    facts.project_context.backend_profile_confidence = 0.98
    facts.project_context.backend_profile_confidence_kind = "structural"
    facts.classes = [
        ClassInfo(
            name="Vote",
            fqcn="App\\Models\\Vote",
            file_path="app/Models/Vote.php",
            file_hash="h4",
        )
    ]
    facts.methods = [
        MethodInfo(
            name="voter",
            class_name="Vote",
            class_fqcn="App\\Models\\Vote",
            file_path="app/Models/Vote.php",
            file_hash="h4",
            call_sites=["$this->belongsTo(SessionParticipant::class)"],
        ),
        MethodInfo(
            name="buildVoteEvents",
            class_name="GameReplayService",
            class_fqcn="App\\Services\\Game\\GameReplayService",
            file_path="app/Services/Game/GameReplayService.php",
            file_hash="svc",
            parameters=["\\Illuminate\\Support\\Collection $votes"],
            call_sites=["$this->replayRepository->getVotesForRound($roundId)"],
        ),
    ]
    facts.relation_accesses = [
        RelationAccess(
            file_path="app/Services/Game/GameReplayService.php",
            line_number=138,
            method_name="buildVoteEvents",
            class_fqcn="App\\Services\\Game\\GameReplayService",
            base_var="$vote",
            relation="voter",
            loop_kind="foreach",
            access_type="property",
        )
    ]

    rule = NPlusOneRiskRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings
    assert findings == []


def test_n_plus_one_still_flags_collection_mapper_with_local_query_context():
    facts = Facts(project_path="x")
    facts.project_context.backend_architecture_profile = "layered"
    facts.classes = [
        ClassInfo(
            name="Vote",
            fqcn="App\\Models\\Vote",
            file_path="app/Models/Vote.php",
            file_hash="h5",
        ),
        ClassInfo(
            name="SessionParticipant",
            fqcn="App\\Models\\SessionParticipant",
            file_path="app/Models/SessionParticipant.php",
            file_hash="h6",
        ),
    ]
    facts.methods = [
        MethodInfo(
            name="voter",
            class_name="Vote",
            class_fqcn="App\\Models\\Vote",
            file_path="app/Models/Vote.php",
            file_hash="h5",
            call_sites=["$this->belongsTo(SessionParticipant::class)"],
        ),
        MethodInfo(
            name="buildVoteEvents",
            class_name="ReplayService",
            class_fqcn="App\\Services\\ReplayService",
            file_path="app/Services/ReplayService.php",
            file_hash="svc2",
            parameters=["\\Illuminate\\Support\\Collection $votes"],
        ),
    ]
    facts.queries = [
        QueryUsage(
            file_path="app/Services/ReplayService.php",
            line_number=120,
            method_name="buildVoteEvents",
            model="Vote",
            method_chain="where->get",
            has_eager_loading=False,
            n_plus_one_risk="high",
        )
    ]
    facts.relation_accesses = [
        RelationAccess(
            file_path="app/Services/ReplayService.php",
            line_number=128,
            method_name="buildVoteEvents",
            class_fqcn="App\\Services\\ReplayService",
            base_var="$vote",
            relation="voter",
            loop_kind="foreach",
            access_type="property",
        )
    ]

    rule = NPlusOneRiskRule(RuleConfig())
    findings = rule.run(facts, project_type="laravel_blade").findings
    assert any(f.rule_id == "n-plus-one-risk" for f in findings)
