from core.context_profiles import ContextProfileMatrix


def test_default_laravel_context_matrix_contains_required_profiles_and_toggles():
    matrix = ContextProfileMatrix.load_default()

    assert matrix.framework == "laravel"
    assert {
        "saas_platform",
        "internal_admin_system",
        "clinic_erp_management",
        "api_backend",
        "realtime_game_control_platform",
        "public_website_with_dashboard",
        "portal_based_business_app",
    }.issubset(set(matrix.project_types.keys()))
    assert {"mvc", "layered", "modular", "api-first"}.issubset(set(matrix.profiles.keys()))

    required_capabilities = {
        "multi_tenant",
        "saas",
        "realtime",
        "billing",
        "multi_role_portal",
        "queue_heavy",
        "mixed_public_dashboard",
        "public_marketing_site",
        "notifications_heavy",
        "external_integrations_heavy",
        "file_upload_storage_heavy",
    }
    assert required_capabilities.issubset(set(matrix.capabilities.keys()))

    required_expectations = {
        "thin_controllers",
        "form_requests_expected",
        "services_actions_expected",
        "repositories_expected",
        "resources_expected",
        "dto_data_objects_preferred",
    }
    assert required_expectations.issubset(set(matrix.team_expectations.keys()))


def test_context_resolution_uses_explicit_over_detected_over_default():
    matrix = ContextProfileMatrix.load_default()

    resolved = matrix.resolve_context(
        explicit_project_type="saas_platform",
        detected_project_type="api_backend",
        detected_project_type_confidence=0.71,
        detected_project_type_confidence_kind="heuristic",
        explicit_profile="layered",
        detected_profile="mvc",
        detected_profile_confidence=0.82,
        detected_profile_confidence_kind="structural",
        explicit_capabilities={"multi_tenant": True},
        detected_capabilities={
            "multi_tenant": (False, 0.2, ["weak tenant token"]),
            "realtime": (True, 0.77, ["ShouldBroadcast in app/Events"]),
        },
        explicit_expectations={"thin_controllers": True},
        detected_expectations={"repositories_expected": (True, 0.65, ["Repository directory present"])},
    )

    assert resolved.project_type == "saas_platform"
    assert resolved.project_type_source == "explicit"
    assert resolved.architecture_profile == "layered"
    assert resolved.architecture_profile_source == "explicit"
    assert resolved.architecture_profile_confidence_kind == "structural"
    assert resolved.capabilities["multi_tenant"].enabled is True
    assert resolved.capabilities["multi_tenant"].source == "explicit"
    assert resolved.capabilities["realtime"].enabled is True
    assert resolved.capabilities["realtime"].source == "detected"
    assert resolved.team_expectations["thin_controllers"].enabled is True
    assert resolved.team_expectations["thin_controllers"].source == "explicit"
    assert resolved.team_expectations["repositories_expected"].enabled is True
    assert resolved.team_expectations["repositories_expected"].source == "detected"


def test_rule_calibration_merges_profile_project_capability_and_team_layers():
    matrix = ContextProfileMatrix.load_default()
    context = matrix.resolve_context(
        explicit_project_type="saas_platform",
        explicit_profile="layered",
        explicit_capabilities={"billing": True, "multi_tenant": True},
        explicit_expectations={"thin_controllers": True},
    )
    calibration = matrix.calibrate_rule("controller-business-logic", context)

    assert calibration["enabled"] is True
    assert calibration["severity"] == "high"
    assert calibration["thresholds"]["min_cyclomatic"] <= 6
    assert any(signal.startswith("profile:") for signal in calibration["signals"])
    assert any(signal.startswith("project_type:") for signal in calibration["signals"])
    assert any(signal.startswith("capability:") for signal in calibration["signals"])
    assert any(signal.startswith("team:") for signal in calibration["signals"])
