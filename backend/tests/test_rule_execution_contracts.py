from pathlib import Path

import pytest

from core.rule_contracts import find_statically_unreachable_rules
from core.rule_engine import RUNTIME_RULES
from core.ruleset import Ruleset


@pytest.mark.parametrize("profile", ["startup", "balanced", "strict"])
def test_shipped_profiles_have_no_statically_unreachable_enabled_rules(profile: str) -> None:
    ruleset_path = Path(__file__).parents[1] / "rulesets" / f"{profile}.yaml"
    ruleset = Ruleset.load(ruleset_path)

    unreachable = find_statically_unreachable_rules(RUNTIME_RULES, ruleset)

    assert unreachable == [], (
        "Enabled rules can never pass their profile confidence filter: "
        + ", ".join(
            f"{item.rule_id} ({item.confidence_ceiling:.2f} < {item.required_floor:.2f})"
            for item in unreachable
        )
    )


def test_every_runtime_rule_has_an_explicit_or_generic_context_policy() -> None:
    invalid = {
        rule_id: getattr(rule_class, "context_policy", None)
        for rule_id, rule_class in RUNTIME_RULES.items()
        if getattr(rule_class, "context_policy", None) not in {"auto", "adaptive", "independent"}
    }

    assert invalid == {}
