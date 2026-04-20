"""Rule registry drift diagnostics (manual vs auto-discovered)."""

from __future__ import annotations

from typing import Any

from core.rule_engine import ALL_RULES, DISCOVERED_RULES


def get_rule_registry_drift() -> dict[str, Any]:
    manual_ids = set(ALL_RULES.keys())
    discovered_ids = set(DISCOVERED_RULES.keys())
    pending_discovered = sorted(discovered_ids - manual_ids)
    manual_only = sorted(manual_ids - discovered_ids)
    return {
        "manual_count": len(manual_ids),
        "discovered_count": len(discovered_ids),
        "pending_discovered": pending_discovered,
        "manual_only": manual_only,
    }
