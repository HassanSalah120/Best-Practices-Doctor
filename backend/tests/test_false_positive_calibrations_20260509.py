from __future__ import annotations

from pathlib import Path

import pytest

from core.ruleset import RuleConfig
from rules.laravel.error_pages_missing import ErrorPagesMissingRule
from rules.react.client_side_auth_only import ClientSideAuthOnlyRule
from rules.react.console_log_in_production_code import ConsoleLogInProductionCodeRule
from rules.react.jsx_tree_sitter import JsxTreeSitterHelper
from rules.react.modal_trap_focus import ModalTrapFocusRule
from rules.react.no_array_index_key import NoArrayIndexKeyRule
from rules.react.no_direct_useeffect import NoDirectUseEffectRule
from rules.react.token_storage_insecure_localstorage import TokenStorageInsecureLocalStorageRule
from rules.react.wcag_apg_ast_rules import DialogFocusRestoreMissingRule
from schemas.facts import Facts, RouteInfo

AST_READY = JsxTreeSitterHelper().is_ready()


@pytest.mark.skipif(not AST_READY, reason="tree-sitter JSX parser is unavailable")
def test_radix_dialog_consumers_do_not_trigger_focus_contract_rules(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    dialog = root / "frontend" / "src" / "components" / "ui" / "dialog.tsx"
    page = root / "frontend" / "src" / "pages" / "Answers.tsx"
    dialog.parent.mkdir(parents=True)
    page.parent.mkdir(parents=True)
    dialog.write_text(
        """
import * as DialogPrimitive from '@radix-ui/react-dialog';

export const Dialog = DialogPrimitive.Root;
export const DialogContent = DialogPrimitive.Content;
""",
        encoding="utf-8",
    )
    content = """
import { Dialog, DialogContent } from '@/components/ui/dialog';

export function Answers() {
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent>
        <button>Close</button>
      </DialogContent>
    </Dialog>
  );
}
"""
    page.write_text(content, encoding="utf-8")
    facts = Facts(project_path=str(root))

    assert ModalTrapFocusRule(RuleConfig()).analyze_ast(str(page), content, facts) == []
    assert DialogFocusRestoreMissingRule(RuleConfig()).analyze_ast(str(page), content, facts) == []


def test_error_pages_missing_accepts_react_router_spa_not_found(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    app = root / "client" / "router" / "Shell.tsx"
    not_found = root / "client" / "views" / "NotFound.tsx"
    app.parent.mkdir(parents=True)
    not_found.parent.mkdir(parents=True)
    app.write_text(
        """
import { Route, Routes } from 'react-router-dom';
import NotFound from './pages/NotFound';

export default function App() {
  return <Routes><Route path="*" element={<NotFound />} /></Routes>;
}
""",
        encoding="utf-8",
    )
    not_found.write_text("export default function NotFound() { return <main>Not found</main>; }", encoding="utf-8")
    facts = Facts(project_path=str(root))
    facts.files = [
        "client/router/Shell.tsx",
        "client/views/NotFound.tsx",
        "routes/web.php",
    ]

    assert ErrorPagesMissingRule(RuleConfig()).run(facts).findings == []


def test_no_direct_useeffect_allows_dedicated_websocket_hook_with_cleanup() -> None:
    content = """
import { useEffect } from 'react';
import { io } from 'socket.io-client';

export function useLiveVotingSocket(activeQuestion, selectedQuestionId, onResultsUpdated) {
  useEffect(() => {
    if (!activeQuestion || selectedQuestionId !== activeQuestion.questionId) return;
    const socket = io(import.meta.env.VITE_WS_URL, { path: '/wss19' });
    socket.on('resultsUpdated', onResultsUpdated);
    return () => {
      socket.off('resultsUpdated', onResultsUpdated);
      socket.close();
    };
  }, [activeQuestion, selectedQuestionId, onResultsUpdated]);
}
"""
    facts = Facts(project_path="x")
    findings = NoDirectUseEffectRule(RuleConfig()).analyze_ast(
        "frontend/src/realtime/liveVotingSocket.ts",
        content,
        facts,
    )

    assert findings == []


def test_console_log_rule_allows_cli_operator_scripts() -> None:
    content = """
#!/usr/bin/env node
console.log('Creating admin user...');
console.error('Could not connect to database');
"""
    facts = Facts(project_path="x")
    rule = ConsoleLogInProductionCodeRule(RuleConfig())

    assert rule.analyze_regex("tools/admin/create-admin.js", content, facts) == []
    assert rule.analyze_regex("maintenance/backfill-user-publicIds.js", "process.argv; console.log('backfill');", facts) == []


def test_react_no_array_index_key_allows_static_skeleton_literal_values() -> None:
    content = """
export function DashboardSkeleton() {
  return (
    <>{[1, 2, 3].map((i) => (
      <Card key={i} className="border-border/50" />
    ))}</>
  );
}
"""
    facts = Facts(project_path="x")

    assert NoArrayIndexKeyRule(RuleConfig()).analyze_regex("frontend/src/pages/Dashboard.tsx", content, facts) == []


def test_token_storage_rule_allows_preferences_and_client_generated_session_ids() -> None:
    content = """
const saved = localStorage.getItem('hideVotedQuestions');
localStorage.setItem('hideVotedQuestions', JSON.stringify(true));

const existing = localStorage.getItem('chatduell_session_id');
if (!existing) {
  const newId = crypto.randomUUID();
  localStorage.setItem('chatduell_session_id', newId);
}
"""
    facts = Facts(project_path="x")

    assert TokenStorageInsecureLocalStorageRule(RuleConfig()).analyze_regex("frontend/src/pages/Vote.tsx", content, facts) == []


def test_client_side_auth_rule_allows_ui_only_links_when_backend_route_is_authorized() -> None:
    content = """
export function Profile({ user }) {
  const isAdmin = user?.role === 'admin';
  return (
    <>
      <span>{isAdmin ? 'Admin' : 'User'}</span>
      {isAdmin && <Link to="/admin">Admin Tools</Link>}
    </>
  );
}
"""
    facts = Facts(project_path="x")
    facts.routes = [
        RouteInfo(
            method="GET",
            uri="admin",
            name="admin",
            action="AdminController@index",
            middleware=["auth:sanctum", "admin"],
        ),
    ]

    assert ClientSideAuthOnlyRule(RuleConfig()).analyze_regex("frontend/src/pages/Profile.tsx", content, facts) == []
