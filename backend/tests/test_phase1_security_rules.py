"""
Test Phase 1 Security Rules

Tests for cors-misconfiguration, missing-csrf-token-verification, 
insecure-deserialization, and useeffect-cleanup-missing rules.
"""

import pytest
from core.ruleset import RuleConfig
from rules.laravel.cors_misconfiguration import CorsMisconfigurationRule
from rules.laravel.missing_csrf_token_verification import MissingCsrfTokenVerificationRule
from rules.laravel.insecure_deserialization import InsecureDeserializationRule
from rules.react.useeffect_cleanup_missing import UseEffectCleanupMissingRule
from schemas.facts import Facts, RouteInfo


# ============== CORS Misconfiguration Tests ==============

def test_cors_wildcard_with_credentials_flags_critical():
    """Wildcard origin with credentials enabled should be flagged."""
    rule = CorsMisconfigurationRule(RuleConfig())
    content = """
<?php
return [
    'allowed_origins' => ['*'],
    'supports_credentials' => true,
];
"""
    findings = rule.analyze_regex(
        file_path="config/cors.php",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "cors-misconfiguration"
    assert "wildcard" in findings[0].title.lower()
    assert findings[0].confidence >= 0.90


def test_cors_wildcard_without_credentials_flags_warning():
    """Wildcard origin without credentials should be flagged as warning."""
    rule = CorsMisconfigurationRule(RuleConfig())
    content = """
<?php
return [
    'allowed_origins' => ['*'],
    'supports_credentials' => false,
];
"""
    findings = rule.analyze_regex(
        file_path="config/cors.php",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "cors-misconfiguration"


def test_cors_specific_origins_no_flags():
    """Specific origins with credentials should not be flagged."""
    rule = CorsMisconfigurationRule(RuleConfig())
    content = """
<?php
return [
    'allowed_origins' => ['https://example.com', 'https://app.example.com'],
    'supports_credentials' => true,
];
"""
    findings = rule.analyze_regex(
        file_path="config/cors.php",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


def test_cors_non_config_file_skipped():
    """Non-CORS config files should be skipped."""
    rule = CorsMisconfigurationRule(RuleConfig())
    content = """
<?php
return [
    'allowed_origins' => ['*'],
    'supports_credentials' => true,
];
"""
    findings = rule.analyze_regex(
        file_path="app/Http/Controllers/Controller.php",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


# ============== CSRF Token Verification Tests ==============

def test_csrf_missing_on_mutating_route():
    """POST route without web middleware should be flagged."""
    facts = Facts(project_path=".")
    facts.routes.append(
        RouteInfo(
            method="POST",
            uri="/profile/update",
            action="ProfileController@update",
            file_path="routes/web.php",
            line_number=10,
            middleware=["auth"],  # Missing 'web' middleware
        )
    )

    rule = MissingCsrfTokenVerificationRule(RuleConfig())
    findings = rule.analyze(facts)

    assert len(findings) == 1
    assert findings[0].rule_id == "missing-csrf-token-verification"


def test_csrf_present_with_web_middleware():
    """Route with web middleware should not be flagged."""
    facts = Facts(project_path=".")
    facts.routes.append(
        RouteInfo(
            method="POST",
            uri="/profile/update",
            action="ProfileController@update",
            file_path="routes/web.php",
            line_number=10,
            middleware=["web", "auth"],  # Has 'web' middleware
        )
    )

    rule = MissingCsrfTokenVerificationRule(RuleConfig())
    findings = rule.analyze(facts)

    assert len(findings) == 0


def test_csrf_api_route_exempt():
    """API routes should be exempt from CSRF check."""
    facts = Facts(project_path=".")
    facts.routes.append(
        RouteInfo(
            method="POST",
            uri="/api/users",
            action="UserController@store",
            file_path="routes/api.php",
            line_number=10,
            middleware=["api", "auth:sanctum"],
        )
    )

    rule = MissingCsrfTokenVerificationRule(RuleConfig())
    findings = rule.analyze(facts)

    assert len(findings) == 0


def test_csrf_webhook_route_exempt():
    """Webhook routes should be exempt."""
    facts = Facts(project_path=".")
    facts.routes.append(
        RouteInfo(
            method="POST",
            uri="/webhook/stripe",
            action="WebhookController@stripe",
            file_path="routes/web.php",
            line_number=10,
            middleware=[],
        )
    )

    rule = MissingCsrfTokenVerificationRule(RuleConfig())
    findings = rule.analyze(facts)

    assert len(findings) == 0


# ============== Insecure Deserialization Tests ==============

def test_unserialize_user_input_flags():
    """unserialize on user input should be flagged."""
    rule = InsecureDeserializationRule(RuleConfig())
    content = """
<?php
class Controller {
    public function store() {
        $data = unserialize($request->input('data'));
    }
}
"""
    findings = rule.analyze_regex(
        file_path="app/Http/Controllers/Controller.php",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "insecure-deserialization"
    assert findings[0].confidence >= 0.85


def test_unserialize_superglobal_flags():
    """unserialize on superglobals should be flagged."""
    rule = InsecureDeserializationRule(RuleConfig())
    content = """
<?php
$data = unserialize($_GET['payload']);
"""
    findings = rule.analyze_regex(
        file_path="app/script.php",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 1


def test_unserialize_with_allowed_classes_safe():
    """unserialize with allowed_classes should not be flagged."""
    rule = InsecureDeserializationRule(RuleConfig())
    content = """
<?php
$data = unserialize($payload, ['allowed_classes' => [User::class]]);
"""
    findings = rule.analyze_regex(
        file_path="app/Service.php",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


def test_unserialize_test_file_skipped():
    """Test files should be skipped."""
    rule = InsecureDeserializationRule(RuleConfig())
    content = """
<?php
$data = unserialize($_GET['payload']);
"""
    findings = rule.analyze_regex(
        file_path="tests/Feature/ControllerTest.php",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


# ============== UseEffect Cleanup Missing Tests ==============

def test_useeffect_setinterval_without_cleanup():
    """setInterval without cleanup should be flagged."""
    rule = UseEffectCleanupMissingRule(RuleConfig())
    content = """
import { useEffect, useState } from 'react';

function Counter() {
    const [count, setCount] = useState(0);
    
    useEffect(() => {
        setInterval(() => setCount(c => c + 1), 1000);
    }, []);
    
    return <div>{count}</div>;
}
"""
    findings = rule.analyze_regex(
        file_path="src/components/Counter.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "useeffect-cleanup-missing"
    assert "setInterval" in findings[0].context


def test_useeffect_setinterval_with_cleanup_safe():
    """setInterval with cleanup should not be flagged."""
    rule = UseEffectCleanupMissingRule(RuleConfig())
    content = """
import { useEffect, useState } from 'react';

function Counter() {
    const [count, setCount] = useState(0);
    
    useEffect(() => {
        const timer = setInterval(() => setCount(c => c + 1), 1000);
        return () => clearInterval(timer);
    }, []);
    
    return <div>{count}</div>;
}
"""
    findings = rule.analyze_regex(
        file_path="src/components/Counter.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


def test_useeffect_subscription_without_cleanup():
    """Subscription without cleanup should be flagged."""
    rule = UseEffectCleanupMissingRule(RuleConfig())
    content = """
import { useEffect } from 'react';

function Component() {
    useEffect(() => {
        observable.subscribe(data => setData(data));
    }, []);
}
"""
    findings = rule.analyze_regex(
        file_path="src/components/Component.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 1


def test_useeffect_subscription_with_cleanup_safe():
    """Subscription with cleanup should not be flagged."""
    rule = UseEffectCleanupMissingRule(RuleConfig())
    content = """
import { useEffect } from 'react';

function Component() {
    useEffect(() => {
        const sub = observable.subscribe(data => setData(data));
        return () => sub.unsubscribe();
    }, []);
}
"""
    findings = rule.analyze_regex(
        file_path="src/components/Component.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


def test_useeffect_event_listener_without_cleanup():
    """addEventListener without cleanup should be flagged."""
    rule = UseEffectCleanupMissingRule(RuleConfig())
    content = """
import { useEffect } from 'react';

function Component() {
    useEffect(() => {
        window.addEventListener('resize', handleResize);
    }, []);
}
"""
    findings = rule.analyze_regex(
        file_path="src/components/Component.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 1


def test_useeffect_no_side_effects():
    """useEffect without side effects should not be flagged."""
    rule = UseEffectCleanupMissingRule(RuleConfig())
    content = """
import { useEffect } from 'react';

function Component({ userId }) {
    useEffect(() => {
        console.log('User ID changed:', userId);
    }, [userId]);
}
"""
    findings = rule.analyze_regex(
        file_path="src/components/Component.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


def test_useeffect_test_file_skipped():
    """Test files should be skipped."""
    rule = UseEffectCleanupMissingRule(RuleConfig())
    content = """
import { useEffect } from 'react';

function Component() {
    useEffect(() => {
        setInterval(() => {}, 1000);
    }, []);
}
"""
    findings = rule.analyze_regex(
        file_path="src/__tests__/Component.test.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
