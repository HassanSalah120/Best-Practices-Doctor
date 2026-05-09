from __future__ import annotations

from core.ruleset import RuleConfig
from rules.react.status_message_announcement import StatusMessageAnnouncementRule
from schemas.facts import Facts


def test_status_message_rule_skips_transport_service_modules():
    rule = StatusMessageAnnouncementRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export function connectGameSocket(onStatus: (message: string) => void) {
    socket.on("error", (errorMessage) => {
        onStatus(errorMessage);
    });
}
"""

    assert rule.analyze_regex("resources/js/react/services/gameSocket.ts", content, facts) == []


def test_status_message_rule_accepts_component_live_regions():
    rule = StatusMessageAnnouncementRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export function GameBoard({ statusMessage, errorMessage }) {
    return (
        <>
            <div role="status" aria-live="polite">{statusMessage}</div>
            <div role="alert" aria-live="assertive">{errorMessage}</div>
        </>
    );
}
"""

    assert rule.analyze_regex("resources/js/react/components/GameBoard.tsx", content, facts) == []


def test_status_message_rule_flags_rendered_message_without_live_region():
    rule = StatusMessageAnnouncementRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export function GameBoard({ errorMessage }) {
    return <div>{errorMessage}</div>;
}
"""

    findings = rule.analyze_regex("resources/js/react/components/GameBoard.tsx", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "status-message-announcement"
