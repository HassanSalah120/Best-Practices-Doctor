"""
Project-aware recommendation helpers.

These helpers keep guidance consistent across rules while staying architecture- and
business-context-aware.
"""

from __future__ import annotations

from typing import Iterable

from schemas.facts import Facts


def enabled_capabilities(facts: Facts) -> set[str]:
    context = getattr(facts, "project_context", None)
    payload = getattr(context, "backend_capabilities", {}) if context is not None else {}
    out: set[str] = set()
    if not isinstance(payload, dict):
        return out
    for key, value in payload.items():
        if isinstance(value, dict) and bool(value.get("enabled", False)):
            out.add(str(key))
    return out


def enabled_team_standards(facts: Facts) -> set[str]:
    context = getattr(facts, "project_context", None)
    payload = getattr(context, "backend_team_expectations", {}) if context is not None else {}
    out: set[str] = set()
    if not isinstance(payload, dict):
        return out
    for key, value in payload.items():
        if isinstance(value, dict) and bool(value.get("enabled", False)):
            out.add(str(key))
    return out


def project_business_context(facts: Facts) -> str:
    context = getattr(facts, "project_context", None)
    if context is None:
        return "unknown"
    return str(getattr(context, "project_business_context", "unknown") or "unknown")


def project_aware_guidance(facts: Facts, *, focus: str) -> str:
    """
    Return additional recommendation bullets based on detected project/business context.

    focus:
      - "controller_boundaries"
      - "service_boundaries"
      - "orchestration_boundaries"
    """
    business = project_business_context(facts)
    capabilities = enabled_capabilities(facts)
    standards = enabled_team_standards(facts)

    lines: list[str] = []
    if business == "saas_platform":
        lines.extend(
            [
                "- Keep subscription lifecycle transitions in one billing/service boundary.",
                "- Centralize quota enforcement so account/admin/customer paths stay consistent.",
            ]
        )
    elif business == "realtime_game_control_platform":
        lines.extend(
            [
                "- Keep controller endpoints thin and move event/state synchronization to dedicated services.",
                "- Preserve clear websocket auth and event-flow boundaries (controller -> action/service -> broadcaster).",
            ]
        )
    elif business == "clinic_erp_management":
        lines.extend(
            [
                "- Keep workflow transitions explicit (appointments/claims/invoices) inside domain services/actions.",
                "- Preserve role/permission boundaries and auditability in orchestration code paths.",
            ]
        )
    elif business == "portal_based_business_app":
        lines.extend(
            [
                "- Keep portal role boundaries explicit so admin/staff/customer paths cannot drift.",
            ]
        )
    elif business == "api_backend":
        lines.extend(
            [
                "- Keep response-shaping and API contracts separate from domain workflows.",
            ]
        )

    if "multi_tenant" in capabilities:
        lines.append("- Keep tenant scoping centralized in shared services/repositories, not scattered in controllers.")
    if "billing" in capabilities and focus in {"service_boundaries", "orchestration_boundaries"}:
        lines.append("- Keep payment provider integration behind a bounded billing service interface.")
    if "realtime" in capabilities and focus == "orchestration_boundaries":
        lines.append("- Keep realtime dispatch/state transitions in event/listener/job boundaries, not inline in HTTP handlers.")
    if "thin_controllers" in standards and focus == "controller_boundaries":
        lines.append("- Team standard indicates thin controllers: keep controller methods as request -> call -> response only.")
    if "services_actions_expected" in standards and focus in {"controller_boundaries", "service_boundaries"}:
        lines.append("- Team standard expects Services/Actions: extract reusable or workflow-heavy logic into those layers.")

    if not lines:
        return ""

    deduped: list[str] = []
    seen: set[str] = set()
    for line in lines:
        text = str(line or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        deduped.append(text)
    return "\n".join(deduped)


def recommendation_context_tags(facts: Facts) -> list[str]:
    business = project_business_context(facts)
    capabilities = sorted(enabled_capabilities(facts))
    tags = [f"business:{business}"] if business and business != "unknown" else []
    tags.extend(f"capability:{cap}" for cap in capabilities[:6])
    return tags
