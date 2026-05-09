from __future__ import annotations
import pytest
from core.ruleset import RuleConfig
from rules.react.react_seo_expansion_rules import CanonicalMissingOrInvalidRule
from schemas.facts import Facts, ProjectContext

def _public_facts() -> Facts:
    return Facts(
        project_path=".",
        project_context=ProjectContext(
            project_type="public_website_with_dashboard",
            capabilities={
                "mixed_public_dashboard": {"enabled": True, "source": "explicit", "confidence": 0.9},
                "public_marketing_site": {"enabled": True, "source": "explicit", "confidence": 0.9},
            },
        ),
    )

def test_canonical_rule_skips_authenticated_layout():
    rule = CanonicalMissingOrInvalidRule(RuleConfig())
    facts = _public_facts()
    facts.files = ["resources/js/pages/Appointments/Index.tsx"]
    
    # Example 1: Appointments Management (uses AuthenticatedLayout)
    content = """
import { Head } from "@inertiajs/react";
import AuthenticatedLayout from "@/Layouts/AuthenticatedLayout";

export default function AppointmentsIndex() {
    return (
        <AuthenticatedLayout>
            <Head title="Appointments" />
            <div>Content</div>
        </AuthenticatedLayout>
    );
}
"""
    file_path = "resources/js/pages/Appointments/Index.tsx"
    assert rule.analyze_regex(file_path, content, facts) == []

def test_canonical_rule_skips_internal_paths():
    rule = CanonicalMissingOrInvalidRule(RuleConfig())
    facts = _public_facts()
    facts.files = ["resources/js/pages/Clinic/Inventory/Index.tsx"]
    
    # Example 3: Clinic Inventory (path-based exclusion)
    content = """
import { Head } from "@inertiajs/react";

export default function InventoryIndex() {
    return (
        <div>
            <Head title="Inventory" />
            <div>Content</div>
        </div>
    );
}
"""
    file_path = "resources/js/pages/Clinic/Inventory/Index.tsx"
    assert rule.analyze_regex(file_path, content, facts) == []

def test_canonical_rule_flags_public_pages_missing_canonical():
    rule = CanonicalMissingOrInvalidRule(RuleConfig())
    facts = _public_facts()
    facts.files = ["resources/js/pages/Welcome/Index.tsx"]
    
    # Welcome page (no special markers, but in public surface)
    content = """
import { Head } from "@inertiajs/react";

export default function Welcome() {
    return (
        <div>
            <Head title="Welcome" />
            <h1>Welcome</h1>
        </div>
    );
}
"""
    file_path = "resources/js/pages/Welcome/Index.tsx"
    findings = rule.analyze_regex(file_path, content, facts)
    assert len(findings) == 1
    assert findings[0].title == "Canonical link is missing on indexable page"

def test_canonical_rule_flags_guest_layout_missing_canonical():
    rule = CanonicalMissingOrInvalidRule(RuleConfig())
    facts = _public_facts()
    facts.files = ["resources/js/pages/Auth/Login.tsx"]
    
    # Auth page using GuestLayout
    content = """
import { Head } from "@inertiajs/react";
import GuestLayout from "@/Layouts/GuestLayout";

export default function Login() {
    return (
        <GuestLayout>
            <Head title="Login" />
            <form>...</form>
        </GuestLayout>
    );
}
"""
    file_path = "resources/js/pages/Auth/Login.tsx"
    findings = rule.analyze_regex(file_path, content, facts)
    assert len(findings) == 1
    assert findings[0].title == "Canonical link is missing on indexable page"

def test_canonical_rule_skips_if_canonical_present():
    rule = CanonicalMissingOrInvalidRule(RuleConfig())
    facts = _public_facts()
    facts.files = ["resources/js/pages/Welcome/Index.tsx"]
    
    content = """
import { Head } from "@inertiajs/react";

export default function Welcome() {
    return (
        <div>
            <Head>
                <title>Welcome</title>
                <link rel="canonical" href="https://example.com/" />
            </Head>
            <h1>Welcome</h1>
        </div>
    );
}
"""
    file_path = "resources/js/pages/Welcome/Index.tsx"
    assert rule.analyze_regex(file_path, content, facts) == []

def test_canonical_rule_accepts_laravel_url_generator_in_blade():
    rule = CanonicalMissingOrInvalidRule(RuleConfig())
    facts = _public_facts()
    facts.files = ["resources/views/react.blade.php"]

    content = """
<!doctype html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
    <head>
        <title>Roll</title>
        <link rel="canonical" href="{{ url('/') }}" />
    </head>
    <body><div id="app"></div></body>
</html>
"""

    assert rule.analyze_regex("resources/views/react.blade.php", content, facts) == []

def test_canonical_rule_handles_dynamic_href():
    rule = CanonicalMissingOrInvalidRule(RuleConfig())
    facts = _public_facts()
    
    # Dynamic href using curly braces
    content = """
import { Head } from "@inertiajs/react";
export default function Login() {
    return <Head><link rel="canonical" href={route("login")} /></Head>;
}
"""
    assert rule.analyze_regex("resources/js/pages/Auth/Login/Index.tsx", content, facts) == []

def test_canonical_rule_flags_portal_if_not_authenticated_layout():
    rule = CanonicalMissingOrInvalidRule(RuleConfig())
    facts = _public_facts()
    facts.files = ["resources/js/pages/Portal/Dashboard/Index.tsx"]
    
    # Portal page (no longer in internal markers)
    content = """
import { Head } from "@inertiajs/react";

export default function PortalDashboard() {
    return (
        <div>
            <Head title="Dashboard" />
            <div>Portal Content</div>
        </div>
    );
}
"""
    file_path = "resources/js/pages/Portal/Dashboard/Index.tsx"
    findings = rule.analyze_regex(file_path, content, facts)
    assert len(findings) == 1
    assert findings[0].title == "Canonical link is missing on indexable page"

def test_is_page_like_segment_matching():
    rule = CanonicalMissingOrInvalidRule(RuleConfig())
    
    # Positive match
    assert rule._is_page_like("resources/js/pages/Home.tsx") is True
    
    # Substring match (should be false now)
    assert rule._is_page_like("resources/js/pagesBackup/Home.tsx") is False
    assert rule._is_page_like("resources/js/screenshots/Home.tsx") is False

def test_child_composition_pascal_case_matching():
    rule = CanonicalMissingOrInvalidRule(RuleConfig())
    
    # Negative: Looks like a component (suffix match)
    assert rule._looks_like_child_composition("resources/js/components/Hero.tsx", "<div>Hero</div>") is True
    assert rule._looks_like_child_composition("resources/js/pages/UserList.tsx", "<div>List</div>") is True
    
    # Positive: Not a child composition (substring but not PascalCase word)
    assert rule._looks_like_child_composition("resources/js/pages/Cardboard.tsx", "<div>Cardboard</div>") is False

def test_canonical_rule_skips_error_pages():
    rule = CanonicalMissingOrInvalidRule(RuleConfig())
    facts = _public_facts()
    
    # Error pages (path-based exclusion)
    assert rule.analyze_regex("resources/js/pages/errors/404.tsx", "<div>404</div>", facts) == []
    assert rule.analyze_regex("resources/js/pages/Error/Show.tsx", "<div>Error</div>", facts) == []

def test_canonical_rule_skips_sensitive_auth_pages():
    rule = CanonicalMissingOrInvalidRule(RuleConfig())
    facts = _public_facts()
    
    # Sensitive auth pages (path-based exclusion)
    assert rule.analyze_regex("resources/js/pages/Auth/ConfirmPassword/Index.tsx", "<Head title='Confirm' />", facts) == []
    assert rule.analyze_regex("resources/js/pages/Auth/TwoFactorChallenge/Index.tsx", "<Head title='2FA' />", facts) == []

def test_canonical_rule_skips_sub_components_and_hooks():
    rule = CanonicalMissingOrInvalidRule(RuleConfig())
    facts = _public_facts()
    
    # Sub-components in pages folder
    assert rule.analyze_regex("resources/js/pages/Welcome/Hero.tsx", "<div>Hero</div>", facts) == []
    assert rule.analyze_regex("resources/js/pages/Welcome/SocialProof.tsx", "<div>Proof</div>", facts) == []
    
    # .components suffix
    assert rule.analyze_regex("resources/js/pages/Portal/Analytics/Index.components.tsx", "<div>Stats</div>", facts) == []
    
    # Hooks (.ts files)
    assert rule.analyze_regex("resources/js/pages/Portal/Clinics/useClinicCreateForm.ts", "export function useForm() {}", facts) == []

def test_canonical_rule_skips_authenticated_portal_pages():
    rule = CanonicalMissingOrInvalidRule(RuleConfig())
    facts = _public_facts()
    
    # Portal page using AuthenticatedLayout (should be skipped)
    content = """
import AuthenticatedLayout from "@/Layouts/AuthenticatedLayout";
export default function Dashboard() {
    return <AuthenticatedLayout><Head title="Dashboard" /></AuthenticatedLayout>;
}
"""
    assert rule.analyze_regex("resources/js/pages/Portal/Dashboard/Index.tsx", content, facts) == []
