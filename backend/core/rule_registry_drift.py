"""Rule registry drift diagnostics (manual vs auto-discovered)."""

from __future__ import annotations

from typing import Any

from core.rule_engine import (
    ALL_RULES,
    DISCOVERED_RULES,
    LEGACY_RULE_ALIASES,
    WRAPPED_INTERNAL_RULES,
    get_unaccounted_discovered_rule_ids,
)


def get_rule_registry_drift() -> dict[str, Any]:
    manual_ids = set(ALL_RULES.keys())
    discovered_ids = set(DISCOVERED_RULES.keys())
    wrapped_internal = sorted(discovered_ids.intersection(WRAPPED_INTERNAL_RULES.keys()))
    pending_discovered = get_unaccounted_discovered_rule_ids(
        discovered_registry=DISCOVERED_RULES,
        manual_registry=ALL_RULES,
    )
    manual_only = sorted(manual_ids - discovered_ids)
    return {
        "manual_count": len(manual_ids),
        "discovered_count": len(discovered_ids),
        "pending_discovered": pending_discovered,
        "manual_only": manual_only,
        "wrapped_internal": wrapped_internal,
        "wrapped_internal_count": len(wrapped_internal),
        "legacy_alias_only": sorted(set(LEGACY_RULE_ALIASES.keys()) - discovered_ids),
        "legacy_alias_only_count": len(set(LEGACY_RULE_ALIASES.keys()) - discovered_ids),
    }
