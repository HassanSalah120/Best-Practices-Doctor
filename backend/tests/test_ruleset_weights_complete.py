from __future__ import annotations

from pathlib import Path

from core.ruleset import Ruleset
from core.scoring import ScoringEngine
from schemas.finding import Category


def _assert_ruleset_has_nonzero_weights(ruleset_path: Path) -> None:
    ruleset = Ruleset.load(ruleset_path)
    scoring = ScoringEngine(ruleset)

    # Default ruleset should be explicit but complete: no category should be
    # accidentally weighted as 0 (which would make action plan priorities 0).
    for cat in Category:
        w = scoring._get_weight(cat)  # intentional: validate engine behavior, not raw YAML keys
        assert w > 0, f"{ruleset_path} missing/non-positive weight for category {cat.value!r} (got {w})"


def test_committed_default_rulesets_have_complete_scoring_weights():
    backend_root = Path(__file__).resolve().parents[1]
    repo_root = backend_root.parent

    _assert_ruleset_has_nonzero_weights(backend_root / "ruleset.default.yaml")
    _assert_ruleset_has_nonzero_weights(repo_root / "ruleset.default.yaml")

