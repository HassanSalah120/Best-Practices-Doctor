"""
Test False Positive Fix for no-dangerously-set-inner-html

Tests that the rule correctly skips comments and only flags actual JSX usage.
"""

import pytest
from core.ruleset import RuleConfig
from rules.react.no_dangerously_set_inner_html import NoDangerouslySetInnerHtmlRule
from schemas.facts import Facts


def test_comment_with_dangerouslySetInnerHTML_not_flagged():
    """Comment mentioning dangerouslySetInnerHTML should NOT be flagged."""
    rule = NoDangerouslySetInnerHtmlRule(RuleConfig())
    content = """
import React from 'react';

/**
 * Pagination component that avoids dangerouslySetInnerHTML and uses stable keys
 */
export const PaginationLinks = ({ links }) => {
    return (
        <div>
            {links.map(link => <span key={link.id}>{link.label}</span>)}
        </div>
    );
};
"""
    findings = rule.analyze_regex(
        file_path="src/components/PaginationLinks.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0, "Comment should not trigger finding"


def test_single_line_comment_not_flagged():
    """Single-line comment mentioning dangerouslySetInnerHTML should NOT be flagged."""
    rule = NoDangerouslySetInnerHtmlRule(RuleConfig())
    content = """
import React from 'react';

// Note: We avoid dangerouslySetInnerHTML for security reasons
export const SafeComponent = () => {
    return <div>Safe content</div>;
};
"""
    findings = rule.analyze_regex(
        file_path="src/components/SafeComponent.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


def test_actual_jsx_usage_flagged():
    """Actual JSX usage of dangerouslySetInnerHTML SHOULD be flagged."""
    rule = NoDangerouslySetInnerHtmlRule(RuleConfig())
    content = """
import React from 'react';

export const UnsafeComponent = ({ html }) => {
    return <div dangerouslySetInnerHTML={{ __html: html }} />;
};
"""
    findings = rule.analyze_regex(
        file_path="src/components/UnsafeComponent.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "no-dangerously-set-inner-html"


def test_multiline_style_tag_usage_flagged():
    """Multiline <style dangerouslySetInnerHTML={...}> usage SHOULD be flagged."""
    rule = NoDangerouslySetInnerHtmlRule(RuleConfig())
    content = """
import React from 'react';

export const UnsafeStyle = () => {
    return (
        <style
            dangerouslySetInnerHTML={{
                __html: `
                    @keyframes spin {
                        from { transform: rotate(0deg); }
                        to { transform: rotate(360deg); }
                    }
                `
            }}
        />
    );
};
"""
    findings = rule.analyze_regex(
        file_path="resources/js/components/UnsafeStyle.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "no-dangerously-set-inner-html"


def test_dompurify_usage_not_flagged():
    """Usage with DOMPurify should NOT be flagged."""
    rule = NoDangerouslySetInnerHtmlRule(RuleConfig())
    content = """
import React from 'react';
import DOMPurify from 'dompurify';

export const SanitizedComponent = ({ html }) => {
    return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
};
"""
    findings = rule.analyze_regex(
        file_path="src/components/SanitizedComponent.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


def test_multiline_comment_not_flagged():
    """Multi-line comment mentioning dangerouslySetInnerHTML should NOT be flagged."""
    rule = NoDangerouslySetInnerHtmlRule(RuleConfig())
    content = """
import React from 'react';

/*
 * This component does NOT use dangerouslySetInnerHTML
 * because it would be a security risk.
 * We use text content instead.
 */
export const SafeComponent = () => {
    return <div>Safe content</div>;
};
"""
    findings = rule.analyze_regex(
        file_path="src/components/SafeComponent.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0


def test_string_literal_not_flagged():
    """String literal mentioning dangerouslySetInnerHTML should NOT be flagged."""
    rule = NoDangerouslySetInnerHtmlRule(RuleConfig())
    content = """
import React from 'react';

const WARNING = "Do not use dangerouslySetInnerHTML without sanitization";

export const WarningComponent = () => {
    return <div>{WARNING}</div>;
};
"""
    findings = rule.analyze_regex(
        file_path="src/components/WarningComponent.tsx",
        content=content,
        facts=Facts(project_path="."),
        metrics=None,
    )

    assert len(findings) == 0, "String literal should not trigger finding"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
