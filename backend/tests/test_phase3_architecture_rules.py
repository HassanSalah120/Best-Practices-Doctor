"""
Test Phase 3 Architecture Rules

Tests for controller-returning-view-in-api, missing-api-resource,
and missing-props-type rules.
"""

import pytest
from core.ruleset import RuleConfig
from rules.laravel.controller_returning_view_in_api import ControllerReturningViewInApiRule
from rules.laravel.missing_api_resource import MissingApiResourceRule
from rules.react.missing_props_type import MissingPropsTypeRule
from schemas.facts import Facts, RouteInfo


# ============== Controller Returning View in API Tests ==============

def test_api_controller_returning_view():
    """API controller returning view should be flagged."""
    rule = ControllerReturningViewInApiRule(RuleConfig())
    content = """
<?php

namespace App\\Http\\Controllers\\Api;

class UserController extends Controller
{
    public function index()
    {
        $users = User::all();
        return view('users.index', compact('users'));
    }
}
"""
    findings = rule.analyze_regex(
        file_path="app/Http/Controllers/Api/UserController.php",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "controller-returning-view-in-api"


def test_api_controller_returning_json_safe():
    """API controller returning JSON should not be flagged."""
    rule = ControllerReturningViewInApiRule(RuleConfig())
    content = """
<?php

namespace App\\Http\\Controllers\\Api;

class UserController extends Controller
{
    public function index()
    {
        $users = User::all();
        return response()->json(['data' => $users]);
    }
}
"""
    findings = rule.analyze_regex(
        file_path="app/Http/Controllers/Api/UserController.php",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


def test_web_controller_returning_view_safe():
    """Web controller returning view should not be flagged."""
    rule = ControllerReturningViewInApiRule(RuleConfig())
    content = """
<?php

namespace App\\Http\\Controllers;

class PageController extends Controller
{
    public function index()
    {
        return view('welcome');
    }
}
"""
    findings = rule.analyze_regex(
        file_path="app/Http/Controllers/PageController.php",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


def test_test_file_skipped():
    """Test files should be skipped."""
    rule = ControllerReturningViewInApiRule(RuleConfig())
    content = """
<?php
return view('users.index');
"""
    findings = rule.analyze_regex(
        file_path="tests/Feature/ApiTest.php",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


# ============== Missing API Resource Tests ==============

def test_api_controller_returning_raw_model():
    """API controller returning raw model should be flagged."""
    rule = MissingApiResourceRule(RuleConfig())
    content = """
<?php

namespace App\\Http\\Controllers\\Api;

class UserController extends Controller
{
    public function index()
    {
        return User::all();
    }
}
"""
    findings = rule.analyze_regex(
        file_path="app/Http/Controllers/Api/UserController.php",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "missing-api-resource"


def test_api_controller_using_resource_safe():
    """API controller using Resource should not be flagged."""
    rule = MissingApiResourceRule(RuleConfig())
    content = """
<?php

namespace App\\Http\\Controllers\\Api;

class UserController extends Controller
{
    public function index()
    {
        return UserResource::collection(User::all());
    }
}
"""
    findings = rule.analyze_regex(
        file_path="app/Http/Controllers/Api/UserController.php",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


def test_api_controller_using_json_response_safe():
    """API controller using json() response should not be flagged."""
    rule = MissingApiResourceRule(RuleConfig())
    content = """
<?php

namespace App\\Http\\Controllers\\Api;

class UserController extends Controller
{
    public function index()
    {
        return response()->json(['data' => User::all()]);
    }
}
"""
    findings = rule.analyze_regex(
        file_path="app/Http/Controllers/Api/UserController.php",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


def test_non_api_controller_skipped():
    """Non-API controllers should be skipped."""
    rule = MissingApiResourceRule(RuleConfig())
    content = """
<?php

namespace App\\Http\\Controllers;

class UserController extends Controller
{
    public function index()
    {
        return User::all();
    }
}
"""
    findings = rule.analyze_regex(
        file_path="app/Http/Controllers/UserController.php",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


# ============== Missing Props Type Tests ==============

def test_component_without_props_type():
    """Component without props type should be flagged."""
    rule = MissingPropsTypeRule(RuleConfig())
    content = """
import { useState } from 'react';

function UserCard({ name, email, isActive }) {
    return (
        <div className="user-card">
            <h2>{name}</h2>
            <p>{email}</p>
        </div>
    );
}

export default UserCard;
"""
    findings = rule.analyze_regex(
        file_path="src/components/UserCard.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "missing-props-type"


def test_component_with_props_interface_safe():
    """Component with Props interface should not be flagged."""
    rule = MissingPropsTypeRule(RuleConfig())
    content = """
import { useState } from 'react';

interface UserCardProps {
    name: string;
    email: string;
    isActive?: boolean;
}

function UserCard({ name, email, isActive = false }: UserCardProps) {
    return (
        <div className="user-card">
            <h2>{name}</h2>
            <p>{email}</p>
        </div>
    );
}

export default UserCard;
"""
    findings = rule.analyze_regex(
        file_path="src/components/UserCard.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


def test_component_with_inline_type_safe():
    """Component with inline type should not be flagged."""
    rule = MissingPropsTypeRule(RuleConfig())
    content = """
const Button = ({ label, onClick }: { label: string; onClick: () => void }) => (
    <button onClick={onClick}>{label}</button>
);

export default Button;
"""
    findings = rule.analyze_regex(
        file_path="src/components/Button.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


def test_component_with_fc_type_safe():
    """Component with FC type should not be flagged."""
    rule = MissingPropsTypeRule(RuleConfig())
    content = """
import { FC } from 'react';

interface ButtonProps {
    label: string;
    onClick: () => void;
}

const Button: FC<ButtonProps> = ({ label, onClick }) => (
    <button onClick={onClick}>{label}</button>
);

export default Button;
"""
    findings = rule.analyze_regex(
        file_path="src/components/Button.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


def test_test_file_skipped():
    """Test files should be skipped."""
    rule = MissingPropsTypeRule(RuleConfig())
    content = """
function UserCard({ name, email }) {
    return <div>{name}</div>;
}
"""
    findings = rule.analyze_regex(
        file_path="src/__tests__/UserCard.test.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


def test_js_file_skipped():
    """JS files should be skipped (only .tsx)."""
    rule = MissingPropsTypeRule(RuleConfig())
    content = """
function UserCard({ name, email }) {
    return <div>{name}</div>;
}
"""
    findings = rule.analyze_regex(
        file_path="src/components/UserCard.js",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
