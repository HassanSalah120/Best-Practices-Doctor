from core.context_profiles import ContextSignalState, EffectiveContext, load_react_context_matrix
from core.pipeline.stages.build_facts import BuildFactsStage
from schemas.project_type import ProjectInfo, ProjectType


def _state(enabled: bool, confidence: float = 0.9, source: str = "detected"):
    return ContextSignalState(enabled=enabled, confidence=confidence, source=source, evidence=["test"])


def test_react_context_matrix_loads():
    matrix = load_react_context_matrix()
    assert matrix.framework == "react"
    assert "inertia_spa" in matrix.project_types


def test_react_calibration_examples():
    matrix = load_react_context_matrix()

    base = EffectiveContext(
        framework="react",
        project_type="standalone",
        architecture_profile="component-driven",
    )

    c1 = base.model_copy(deep=True)
    c1.capabilities["is_public_facing"] = _state(True)
    out1 = matrix.calibrate_rule("missing-aria-live", c1)
    assert out1["severity"] == "high"

    c2 = base.model_copy(deep=True)
    c2.capabilities["has_design_system"] = _state(True)
    out2 = matrix.calibrate_rule("large-react-component", c2)
    assert out2["severity"] == "low"

    c3 = base.model_copy(deep=True)
    c3.capabilities["context_provider_count_high"] = _state(True)
    out3 = matrix.calibrate_rule("context-value-not-memoized", c3)
    assert out3["severity"] == "high"

    c4 = base.model_copy(deep=True)
    c4.capabilities["route_count_large"] = _state(False)
    out4 = matrix.calibrate_rule("missing-route-code-splitting", c4)
    assert out4["enabled"] is False
    c4.capabilities["route_count_large"] = _state(True)
    out5 = matrix.calibrate_rule("missing-route-code-splitting", c4)
    assert out5["enabled"] is True


def test_build_facts_stage_uses_react_matrix_for_react_project():
    stage = BuildFactsStage()
    project = ProjectInfo(
        root_path=".",
        project_type=ProjectType.UNKNOWN,
        has_react_components=True,
        npm_packages={"react": "^18.2.0"},
    )
    matrix = stage._load_context_matrix_for_project(project)
    assert getattr(matrix, "framework", "") == "react"


def test_build_facts_stage_keeps_laravel_matrix_for_laravel_project():
    stage = BuildFactsStage()
    project = ProjectInfo(
        root_path=".",
        project_type=ProjectType.LARAVEL_INERTIA_REACT,
        has_react_components=True,
        npm_packages={"react": "^18.2.0"},
    )
    matrix = stage._load_context_matrix_for_project(project)
    assert getattr(matrix, "framework", "") == "laravel"
