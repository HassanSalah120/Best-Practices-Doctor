"""
Test Phase 2 Performance Rules

Tests for missing-pagination, missing-usememo-for-expensive-calc,
and missing-usecallback-for-event-handlers rules.
"""

import pytest
from core.ruleset import RuleConfig
from rules.laravel.missing_cache_for_reference_data import MissingCacheForReferenceDataRule
from rules.laravel.missing_pagination import MissingPaginationRule
from rules.react.missing_usememo_for_expensive_calc import MissingUseMemoForExpensiveCalcRule
from rules.react.missing_usecallback_for_event_handlers import MissingUseCallbackForEventHandlersRule
from schemas.facts import Facts, MethodInfo, QueryUsage, RouteInfo


# ============== Missing Pagination Tests ==============

def test_missing_cache_for_reference_data_skips_cached_query(tmp_path):
    repo_dir = tmp_path / "app" / "Repositories"
    repo_dir.mkdir(parents=True, exist_ok=True)
    (repo_dir / "SpecialtyRepository.php").write_text(
        """<?php
use Illuminate\\Support\\Facades\\Cache;

class SpecialtyRepository
{
    public function all()
    {
        return Cache::remember('specialties.all', 3600, fn() => Specialty::all());
    }
}
""",
        encoding="utf-8",
    )

    facts = Facts(project_path=str(tmp_path))
    facts.methods.append(
        MethodInfo(
            name="all",
            class_name="SpecialtyRepository",
            class_fqcn="App\\Repositories\\SpecialtyRepository",
            file_path="app/Repositories/SpecialtyRepository.php",
            file_hash="deadbeef",
            call_sites=["Cache::remember('specialties.all', 3600, fn() => Specialty::all())"],
        )
    )
    facts.queries.append(
        QueryUsage(
            model="Specialty",
            method_chain="all()",
            query_type="select",
            file_path="app/Repositories/SpecialtyRepository.php",
            line_number=8,
            method_name="all",
        )
    )

    findings = MissingCacheForReferenceDataRule(RuleConfig()).analyze(facts)
    assert findings == []


def test_missing_cache_for_reference_data_skips_config_facade_reads(tmp_path):
    service_dir = tmp_path / "app" / "Services"
    service_dir.mkdir(parents=True, exist_ok=True)
    (service_dir / "DataRetentionService.php").write_text(
        """<?php
use Illuminate\\Support\\Facades\\Config;

class DataRetentionService
{
    public function __construct()
    {
        $this->retentionPeriods = Config::get('retention.periods', []);
    }
}
""",
        encoding="utf-8",
    )

    facts = Facts(project_path=str(tmp_path))
    facts.methods.append(
        MethodInfo(
            name="__construct",
            class_name="DataRetentionService",
            class_fqcn="App\\Services\\DataRetentionService",
            file_path="app/Services/DataRetentionService.php",
            file_hash="deadbeef",
            call_sites=["Cache::remember('retention.periods', 3600, fn() => [])"],
        )
    )
    facts.queries.append(
        QueryUsage(
            model="Config",
            method_chain="get",
            query_type="select",
            file_path="app/Services/DataRetentionService.php",
            line_number=8,
            method_name="__construct",
        )
    )

    findings = MissingCacheForReferenceDataRule(RuleConfig()).analyze(facts)
    assert findings == []


def test_missing_pagination_on_large_model():
    """Query returning all records on large model should be flagged."""
    facts = Facts(project_path=".")
    facts.routes.append(
        RouteInfo(
            method="GET",
            uri="api/patients",
            action="PatientController@index",
            file_path="routes/api.php",
            line_number=7,
        )
    )
    facts.queries.append(
        QueryUsage(
            model="Patient",
            method_chain="all()",
            query_type="select",
            file_path="app/Http/Controllers/PatientController.php",
            line_number=15,
            method_name="index",
        )
    )

    rule = MissingPaginationRule(RuleConfig())
    findings = rule.analyze(facts)

    assert len(findings) == 1
    assert findings[0].rule_id == "missing-pagination"
    assert "pagination" in findings[0].title.lower()


def test_missing_pagination_with_get():
    """Query using get() without pagination should be flagged."""
    facts = Facts(project_path=".")
    facts.routes.append(
        RouteInfo(
            method="GET",
            uri="api/users",
            action="UserController@index",
            file_path="routes/api.php",
            line_number=11,
        )
    )
    facts.queries.append(
        QueryUsage(
            model="User",
            method_chain="where('active', true)->get()",
            query_type="select",
            file_path="app/Http/Controllers/UserController.php",
            line_number=20,
            method_name="index",
        )
    )

    rule = MissingPaginationRule(RuleConfig())
    findings = rule.analyze(facts)

    assert len(findings) == 1


def test_pagination_present_safe():
    """Query with paginate() should not be flagged."""
    facts = Facts(project_path=".")
    facts.queries.append(
        QueryUsage(
            model="Patient",
            method_chain="paginate(15)",
            query_type="select",
            file_path="app/Http/Controllers/PatientController.php",
            line_number=15,
            method_name="index",
        )
    )

    rule = MissingPaginationRule(RuleConfig())
    findings = rule.analyze(facts)

    assert len(findings) == 0


def test_limit_present_safe():
    """Query with limit() should not be flagged."""
    facts = Facts(project_path=".")
    facts.queries.append(
        QueryUsage(
            model="User",
            method_chain="limit(100)->get()",
            query_type="select",
            file_path="app/Http/Controllers/UserController.php",
            line_number=20,
            method_name="index",
        )
    )

    rule = MissingPaginationRule(RuleConfig())
    findings = rule.analyze(facts)

    assert len(findings) == 0


def test_non_controller_skipped():
    """Non-controller files should be skipped."""
    facts = Facts(project_path=".")
    facts.queries.append(
        QueryUsage(
            model="Patient",
            method_chain="Patient::all()",
            query_type="select",
            file_path="app/Services/PatientService.php",
            line_number=15,
            method_name="getAll",
        )
    )

    rule = MissingPaginationRule(RuleConfig())
    findings = rule.analyze(facts)

    assert len(findings) == 0


def test_test_file_skipped():
    """Test files should be skipped."""
    facts = Facts(project_path=".")
    facts.queries.append(
        QueryUsage(
            model="Patient",
            method_chain="Patient::all()",
            query_type="select",
            file_path="tests/Feature/PatientControllerTest.php",
            line_number=15,
            method_name="test_index",
        )
    )

    rule = MissingPaginationRule(RuleConfig())
    findings = rule.analyze(facts)

    assert len(findings) == 0


# ============== Missing UseMemo Tests ==============

def test_filter_map_without_usememo():
    """filter().map() without useMemo should be flagged."""
    rule = MissingUseMemoForExpensiveCalcRule(RuleConfig())
    content = """
import { useState } from 'react';

function UserList({ users }) {
    const [filter, setFilter] = useState('');
    
    const filteredUsers = users.filter(u => u.active).map(u => ({ ...u, display: u.name }));
    
    return <div>{filteredUsers.map(u => <span key={u.id}>{u.display}</span>)}</div>;
}
"""
    findings = rule.analyze_regex(
        file_path="src/components/UserList.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "missing-usememo-for-expensive-calc"


def test_reduce_without_usememo():
    """reduce() without useMemo should be flagged."""
    rule = MissingUseMemoForExpensiveCalcRule(RuleConfig())
    content = """
function Cart({ items }) {
    const total = items.reduce((sum, item) => sum + item.price, 0);
    return <div>Total: {total}</div>;
}
"""
    findings = rule.analyze_regex(
        file_path="src/components/Cart.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 1


def test_with_usememo_safe():
    """Code with useMemo should not be flagged."""
    rule = MissingUseMemoForExpensiveCalcRule(RuleConfig())
    content = """
import { useMemo } from 'react';

function UserList({ users }) {
    const filteredUsers = useMemo(() => {
        return users.filter(u => u.active);
    }, [users]);
    
    return <div>{filteredUsers.map(u => <span key={u.id}>{u.name}</span>)}</div>;
}
"""
    findings = rule.analyze_regex(
        file_path="src/components/UserList.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


def test_non_component_skipped():
    """Non-component files should be skipped."""
    rule = MissingUseMemoForExpensiveCalcRule(RuleConfig())
    content = """
const utils = {
    processItems: (items) => items.filter(x => x.active)
};
export { utils };
"""
    findings = rule.analyze_regex(
        file_path="src/utils/helpers.ts",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


def test_object_entries_meta_render_is_not_treated_as_expensive():
    rule = MissingUseMemoForExpensiveCalcRule(RuleConfig())
    content = """
function TimelineItem({ item }) {
    return (
        <div>
            {Object.entries(item.meta ?? {}).map(([k, v]) => (
                <span key={`${item.id}-${k}`}>{v}</span>
            ))}
        </div>
    );
}
"""

    findings = rule.analyze_regex(
        file_path="resources/js/pages/Patients/Show.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert findings == []


def test_missing_usememo_skips_plain_typescript_utility_module():
    rule = MissingUseMemoForExpensiveCalcRule(RuleConfig())
    content = """
export function clampChannel(value: number): number {
    return Math.max(0, Math.min(255, value));
}
"""

    findings = rule.analyze_regex(
        file_path="resources/js/utilities/branding.ts",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert findings == []


def test_missing_usememo_skips_concise_usememo_expressions():
    rule = MissingUseMemoForExpensiveCalcRule(RuleConfig())
    content = """
import { useMemo } from 'react';

function VotingBottomPanel({ participants, currentUserId, selectedVoteTarget, t }) {
    const alivePlayers = useMemo(
        () => participants.filter((participant) => !participant.is_eliminated),
        [participants]
    );

    const voteTargets = useMemo(
        () => alivePlayers.filter((participant) => participant.user_id !== currentUserId),
        [alivePlayers, currentUserId]
    );

    const selectedPlayer = useMemo(
        () => typeof selectedVoteTarget === 'number'
            ? alivePlayers.find((participant) => participant.id === selectedVoteTarget) ?? null
            : null,
        [alivePlayers, selectedVoteTarget]
    );

    return <div>{voteTargets.length}</div>;
}
"""

    findings = rule.analyze_regex(
        file_path="resources/js/Components/Game/VotingBottomPanel.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert findings == []


# ============== Missing UseCallback Tests ==============

def test_inline_onclick_without_usecallback():
    """Inline handlers on native DOM elements should not be flagged by default."""
    rule = MissingUseCallbackForEventHandlersRule(RuleConfig())
    content = """
function Button({ id }) {
    return (
        <button onClick={() => console.log(id)}>
            Click me
        </button>
    );
}
"""
    findings = rule.analyze_regex(
        file_path="src/components/Button.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert findings == []


def test_inline_onchange_without_usecallback():
    """Native input handlers are fine without useCallback."""
    rule = MissingUseCallbackForEventHandlersRule(RuleConfig())
    content = """
function Form() {
    return (
        <input onChange={(e) => setValue(e.target.value)} />
    );
}
"""
    findings = rule.analyze_regex(
        file_path="src/components/Form.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert findings == []


def test_with_usecallback_safe():
    """Handler with useCallback should not be flagged."""
    rule = MissingUseCallbackForEventHandlersRule(RuleConfig())
    content = """
import { useCallback } from 'react';

function Button({ id, onSelect }) {
    const handleClick = useCallback(() => {
        onSelect(id);
    }, [id, onSelect]);
    
    return <button onClick={handleClick}>Click me</button>;
}
"""
    findings = rule.analyze_regex(
        file_path="src/components/Button.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


def test_custom_component_handler_in_list_is_flagged():
    """Inline handlers passed to memoized custom components should be flagged."""
    rule = MissingUseCallbackForEventHandlersRule(RuleConfig())
    content = """
import { memo } from 'react';

const AppointmentCard = memo(function AppointmentCard({ onSelect }) {
    return <button onClick={onSelect}>Open</button>;
});

function AppointmentList({ items, onSelect }) {
    return (
        <div>
            {items.map((item) => (
                <AppointmentCard key={item.id} onSelect={() => onSelect(item.id)} />
            ))}
        </div>
    );
}
"""
    findings = rule.analyze_regex(
        file_path="src/components/AppointmentList.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "missing-usecallback-for-event-handlers"
    assert findings[0].confidence >= 0.80


def test_non_memoized_custom_component_handler_is_not_flagged():
    """Custom component handlers without memoized children are too low-signal to flag."""
    rule = MissingUseCallbackForEventHandlersRule(RuleConfig())
    content = """
function AppointmentCard({ onSelect }) {
    return <button onClick={onSelect}>Open</button>;
}

function AppointmentList({ item, onSelect }) {
    return <AppointmentCard onSelect={async () => onSelect(item.id)} />;
}
"""
    findings = rule.analyze_regex(
        file_path="src/components/AppointmentList.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert findings == []


def test_test_file_skipped():
    """Test files should be skipped."""
    rule = MissingUseCallbackForEventHandlersRule(RuleConfig())
    content = """
function Button({ id }) {
    return <button onClick={() => console.log(id)}>Click</button>;
}
"""
    findings = rule.analyze_regex(
        file_path="src/__tests__/Button.test.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
