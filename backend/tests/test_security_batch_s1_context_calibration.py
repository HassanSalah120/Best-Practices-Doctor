from __future__ import annotations

from pathlib import Path

from core.context_profiles import ContextProfileMatrix
from core.ruleset import Ruleset


S1_RULES = [
    "ssrf-risk-http-client",
    "path-traversal-file-access",
    "insecure-file-download-response",
    "webhook-signature-missing",
    "idor-risk-missing-ownership-check",
    "sensitive-route-rate-limit-missing",
    "sanctum-token-scope-missing",
    "session-fixation-regenerate-missing",
    "weak-password-policy-validation",
    "upload-mime-extension-mismatch",
    "archive-upload-zip-slip-risk",
    "upload-size-limit-missing",
    "insecure-postmessage-origin-wildcard",
    "token-storage-insecure-localstorage",
    "client-open-redirect-unvalidated-navigation",
]


def _context(
    matrix: ContextProfileMatrix,
    *,
    project_type: str,
    profile: str,
    capabilities: dict[str, bool] | None = None,
) -> object:
    return matrix.resolve_context(
        explicit_project_type=project_type,
        explicit_profile=profile,
        explicit_capabilities=capabilities or {},
    )


def test_s1_matrix_includes_upload_capability_and_rule_entries():
    matrix = ContextProfileMatrix.load_default()
    assert "file_upload_storage_heavy" in matrix.capabilities
    for rule_id in S1_RULES:
        assert rule_id in matrix.rule_behavior


def test_s1_capability_gated_rules_stay_off_in_mvc_admin_context():
    matrix = ContextProfileMatrix.load_default()
    context = _context(
        matrix,
        project_type="internal_admin_system",
        profile="mvc",
        capabilities={
            "external_integrations_heavy": False,
            "mixed_public_dashboard": False,
            "public_marketing_site": False,
            "multi_role_portal": False,
            "file_upload_storage_heavy": False,
            "multi_tenant": False,
        },
    )

    for rule_id in [
        "ssrf-risk-http-client",
        "webhook-signature-missing",
        "idor-risk-missing-ownership-check",
        "sensitive-route-rate-limit-missing",
        "sanctum-token-scope-missing",
        "upload-mime-extension-mismatch",
        "archive-upload-zip-slip-risk",
        "upload-size-limit-missing",
        "insecure-postmessage-origin-wildcard",
        "token-storage-insecure-localstorage",
        "client-open-redirect-unvalidated-navigation",
    ]:
        calibration = matrix.calibrate_rule(rule_id, context)
        assert calibration.get("enabled") is False


def test_s1_rules_enable_for_layered_saas_portal_context():
    matrix = ContextProfileMatrix.load_default()
    context = _context(
        matrix,
        project_type="saas_platform",
        profile="layered",
        capabilities={
            "external_integrations_heavy": True,
            "mixed_public_dashboard": True,
            "public_marketing_site": True,
            "multi_role_portal": True,
            "file_upload_storage_heavy": True,
            "multi_tenant": True,
        },
    )

    for rule_id in S1_RULES:
        calibration = matrix.calibrate_rule(rule_id, context)
        assert calibration.get("enabled") is True


def test_s1_api_first_context_enables_sanctum_scope_rule():
    matrix = ContextProfileMatrix.load_default()
    context = _context(
        matrix,
        project_type="api_backend",
        profile="api-first",
        capabilities={"multi_role_portal": True},
    )
    calibration = matrix.calibrate_rule("sanctum-token-scope-missing", context)
    assert calibration.get("enabled") is True
    assert calibration.get("severity") == "high"


def test_s1_mixed_public_dashboard_context_enables_hijack_frontend_rules():
    matrix = ContextProfileMatrix.load_default()
    context = _context(
        matrix,
        project_type="public_website_with_dashboard",
        profile="layered",
        capabilities={"mixed_public_dashboard": True},
    )
    for rule_id in [
        "insecure-postmessage-origin-wildcard",
        "token-storage-insecure-localstorage",
        "client-open-redirect-unvalidated-navigation",
    ]:
        calibration = matrix.calibrate_rule(rule_id, context)
        assert calibration.get("enabled") is True


def test_s1_stage1_rollout_profiles_startup_off_strict_on():
    root = Path(__file__).resolve().parents[1]
    startup = Ruleset.load(root / "rulesets" / "startup.yaml")
    strict = Ruleset.load(root / "rulesets" / "strict.yaml")

    for rule_id in S1_RULES:
        assert startup.get_rule_config(rule_id).enabled is False
        assert strict.get_rule_config(rule_id).enabled is True
