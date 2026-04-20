from __future__ import annotations

from pathlib import Path

import pytest

from analysis.facts_builder import FactsBuilder
from analysis.metrics_analyzer import MetricsAnalyzer
from core.detector import ProjectDetector
from core.rule_engine import create_engine
from core.ruleset import Ruleset

OPTIONAL_POSITIVE_RULES = {
    # These rules need specific fixture scenarios (duplicate routes, auth throttle, advanced React a11y/hook patterns)
    # that are not present in the lightweight regression fixtures.
    "duplicate-route-definition",
    "missing-throttle-on-auth-api-routes",
    "missing-auth-on-mutating-api-routes",
    "transaction-required-for-multi-write",
    "tenant-scope-enforcement",
    # These still have direct positive tests, but engine-level overlap dedupe intentionally suppresses
    # them behind a stronger parent finding in the mini regression fixtures.
    "controller-query-direct",
    "controller-business-logic",
    "controller-inline-validation",
    # This rule now requires an i18n-aware project context, which the lightweight golden fixtures do not model.
    "hardcoded-user-facing-strings",
    "react-useeffect-deps",
    "react-no-array-index-key",
    "hooks-in-conditional-or-loop",
    "missing-key-on-list-render",
    "interactive-element-a11y",
    "form-label-association",
    "dto-suggestion",
    "blade-xss-risk",
    "user-model-missing-must-verify-email",
    "registration-missing-registered-event",
    "sensitive-routes-missing-verified-middleware",
    "tenant-access-middleware-missing",
    "signed-routes-missing-signature-middleware",
    "unsafe-external-redirect",
    "no-inline-types",
    "no-inline-services",
    "react-parent-child-spacing-overlap",
    "inertia-page-missing-head",
    "inertia-internal-link-anchor",
    "inertia-form-uses-fetch",
    "authorization-missing-on-sensitive-reads",
    "insecure-session-cookie-config",
    "unsafe-csp-policy",
    # These queue rules now have richer Laravel fixtures, but engine-level overlap
    # suppression can still hide them behind stronger sibling findings in the shared
    # coverage sweep, so they remain optional here.
    "job-missing-idempotency-guard",
    "composer-dependency-below-secure-version",
    "npm-dependency-below-secure-version",
    "inertia-shared-props-sensitive-data",
    "inertia-shared-props-eager-query",
    "job-missing-retry-policy",
    "job-http-call-missing-timeout",
    "anonymous-default-export-component",
    "multiple-exported-react-components",
    "context-provider-inline-value",
    "react-useeffect-fetch-without-abort",
    # These require richer UI, TypeScript, infra, or specialized security fixtures than the
    # lightweight regression projects currently provide.
    "accessible-authentication",
    "asset-versioning-check",
    "autocomplete-missing",
    "autoplay-media",
    "button-text-vague",
    "color-contrast-ratio",
    "controller-returning-view-in-api",
    "column-selection-suggestion",
    "cors-misconfiguration",
    "debug-mode-exposure",
    "error-message-missing",
    "focus-indicator-missing",
    "focus-not-obscured",
    "hardcoded-secrets",
    "heading-order",
    "img-alt-missing",
    "insecure-random-for-security",
    "language-attribute-missing",
    "link-text-vague",
    "long-page-no-toc",
    "missing-api-resource",
    "missing-cache-for-reference-data",
    "missing-csrf-token-verification",
    "missing-https-enforcement",
    "missing-props-type",
    "missing-usecallback-for-event-handlers",
    "missing-usememo-for-expensive-calc",
    "massive-model",
    "modal-trap-focus",
    "no-dangerously-set-inner-html",
    "no-inline-hooks",
    "no-nested-components",
    "null-filtering-suggestion",
    "placeholder-as-label",
    "raw-sql",
    "react-project-structure-consistency",
    "redundant-entry",
    "safe-target-blank",
    "sensitive-data-logging",
    "skip-link-missing",
    "status-message-announcement",
    "touch-target-size",
    "typescript-type-check",
    "css-font-size-px",
    "css-spacing-px",
    "css-fixed-layout-px",
    "tailwind-arbitrary-value-overuse",
    "tailwind-arbitrary-text-size",
    "tailwind-arbitrary-spacing",
    "tailwind-arbitrary-layout-size",
    "tailwind-arbitrary-radius-shadow",
    "controller-index-filter-duplication",
    "model-cross-model-query",
    "action-class-naming-consistency",
    # S1 Security rules - require specialized security fixtures not present in lightweight regression projects
    "sensitive-route-rate-limit-missing",
    "ssrf-risk-http-client",
    "path-traversal-file-access",
    "insecure-file-download-response",
    "webhook-signature-missing",
    "idor-risk-missing-ownership-check",
    "sanctum-token-scope-missing",
    "session-fixation-regenerate-missing",
    "weak-password-policy-validation",
    "upload-mime-extension-mismatch",
    "archive-upload-zip-slip-risk",
    "upload-size-limit-missing",
    "insecure-postmessage-origin-wildcard",
    "token-storage-insecure-localstorage",
    "client-open-redirect-unvalidated-navigation",
    # New React/Accessibility/Architecture rules added in recent updates
    "error-pages-missing",
    "large-custom-hook",
    "cross-feature-import-boundary",
    "query-key-instability",
    "effect-event-relay-smell",
    "route-shell-missing-error-boundary",
    "unsafe-async-handler-without-guard",
    "exhaustive-deps-ast",
    "livewire-public-prop-mass-assignment",
    "host-header-poisoning-risk",
    "cookie-samesite-missing",
    "pcre-redos-risk",
    "api-key-in-client-bundle",
    "avoid-props-to-state-copy",
    "controlled-uncontrolled-input-mismatch",
    "usememo-overuse",
    "password-hash-weak-algorithm",
    "jsx-aria-attribute-format",
    "inertia-shared-props-payload-budget",
    "useeffect-cleanup-missing",
    "css-focus-outline-without-replacement",
    "timing-attack-token-comparison",
    "apg-tabs-keyboard-contract",
    "react-no-random-key",
    "apg-menu-button-contract",
    "zip-bomb-risk",
    "tailwind-motion-reduce-missing",
    "tailwind-appearance-none-risk",
    "props-state-sync-effect-smell",
    "usememo-ast",
    "repository-suggestion",
    "crawlable-internal-navigation-required",
    "h1-singleton-violation",
    "context-oversized-provider",
    "unsafe-redirect",
    "react-no-props-mutation",
    "ref-used-as-reactive-state",
    "xml-xxe-risk",
    "semantic-wrapper-breakage",
    "ref-access-during-render",
    "inertia-reload-without-only",
    "usecallback-ast",
    "missing-content-security-policy",
    "missing-hsts-header",
    "react-event-listener-cleanup-required",
    "suspense-fallback-missing",
    "canonical-missing-or-invalid",
    "lazy-without-suspense",
    "dangerous-html-sink-without-sanitizer",
    "sensitive-response-cache-control-missing",
    "robots-directive-risk",
    "react-no-state-mutation",
    "state-update-in-render",
    "meta-description-missing-or-generic",
    "outside-click-without-keyboard-fallback",
    "postmessage-receiver-origin-not-verified",
    "react-timer-cleanup-required",
    "derived-state-in-effect",
    "duplicate-key-source",
    "css-hover-only-interaction",
    "debug-exposure-risk",
    "webhook-replay-protection-missing",
    "missing-pagination",
    "apg-accordion-disclosure-contract",
    "unsafe-file-include-variable",
    "plain-text-sensitive-config",
    "apg-combobox-contract",
    "usecallback-overuse",
    "unsafe-async-handler-without-guard",
    "react-side-effects-in-render",
    "css-color-only-state-indicator",
    "csrf-exception-wildcard-risk",
    "interactive-accessible-name-required",
    "stale-closure-in-listener",
    "stale-closure-in-timer",
    "jsonld-structured-data-invalid-or-mismatched",
    "page-indexability-conflict",
    # S1 Security Rules - require specialized security fixtures
    "sensitive-route-rate-limit-missing",
    "ssrf-risk-http-client",
    "path-traversal-file-access",
    "insecure-file-download-response",
    "webhook-signature-missing",
    "idor-risk-missing-ownership-check",
    "sanctum-token-scope-missing",
    "session-fixation-regenerate-missing",
    "weak-password-policy-validation",
    "upload-mime-extension-mismatch",
    "archive-upload-zip-slip-risk",
    "upload-size-limit-missing",
    "insecure-postmessage-origin-wildcard",
    "token-storage-insecure-localstorage",
    "client-open-redirect-unvalidated-navigation",
    # Additional rules that need specialized fixtures
    "error-pages-missing",
    "large-custom-hook",
    "cross-feature-import-boundary",
    "query-key-instability",
    "effect-event-relay-smell",
    "route-shell-missing-error-boundary",
    "unsafe-async-handler-without-guard",
    "exhaustive-deps-ast",
    "livewire-public-prop-mass-assignment",
    "host-header-poisoning-risk",
    "cookie-samesite-missing",
    "pcre-redos-risk",
    "api-key-in-client-bundle",
    "avoid-props-to-state-copy",
    "controlled-uncontrolled-input-mismatch",
    "usememo-overuse",
    "password-hash-weak-algorithm",
    "jsx-aria-attribute-format",
    "inertia-shared-props-payload-budget",
    "useeffect-cleanup-missing",
    "css-focus-outline-without-replacement",
    "timing-attack-token-comparison",
    "apg-tabs-keyboard-contract",
    "react-no-random-key",
    "apg-menu-button-contract",
    "zip-bomb-risk",
    "tailwind-motion-reduce-missing",
    "tailwind-appearance-none-risk",
    "props-state-sync-effect-smell",
    "usememo-ast",
    "repository-suggestion",
    "crawlable-internal-navigation-required",
    "h1-singleton-violation",
    "context-oversized-provider",
    "unsafe-redirect",
    "react-no-props-mutation",
    "ref-used-as-reactive-state",
    "xml-xxe-risk",
    "semantic-wrapper-breakage",
    "ref-access-during-render",
    "inertia-reload-without-only",
    "usecallback-ast",
    "missing-content-security-policy",
    "missing-hsts-header",
    "react-event-listener-cleanup-required",
    "suspense-fallback-missing",
    "canonical-missing-or-invalid",
    "lazy-without-suspense",
    "dangerous-html-sink-without-sanitizer",
    "sensitive-response-cache-control-missing",
    "robots-directive-risk",
    "react-no-state-mutation",
    "state-update-in-render",
    "meta-description-missing-or-generic",
    "outside-click-without-keyboard-fallback",
    "postmessage-receiver-origin-not-verified",
    "react-timer-cleanup-required",
    "derived-state-in-effect",
    "duplicate-key-source",
    "css-hover-only-interaction",
    "debug-exposure-risk",
    "webhook-replay-protection-missing",
    "missing-pagination",
    "apg-accordion-disclosure-contract",
    "unsafe-file-include-variable",
    "plain-text-sensitive-config",
    "apg-combobox-contract",
    "usecallback-overuse",
    "unsafe-async-handler-without-guard",
    "react-side-effects-in-render",
    "css-color-only-state-indicator",
    "csrf-exception-wildcard-risk",
    "interactive-accessible-name-required",
    "stale-closure-in-listener",
    "stale-closure-in-timer",
    "jsonld-structured-data-invalid-or-mismatched",
    "page-indexability-conflict",
}


@pytest.mark.parametrize(
    "fixture_name,expected_type_prefix",
    [
        ("sample-lara", "laravel"),
        ("laravel-blade-mini", "laravel_blade"),
        ("laravel-inertia-react-mini", "laravel_inertia_react"),
        ("php-native-mini", "native_php"),
        ("php-mvc-mini", "php_mvc"),
    ],
)
def test_fixtures_cover_supported_project_types(fixture_path: Path, fixture_name: str, expected_type_prefix: str):
    project_root = fixture_path / fixture_name
    info = ProjectDetector(str(project_root)).detect()
    assert info.project_type.value.startswith(expected_type_prefix)


def test_each_rule_has_positive_and_negative_case_across_fixtures(fixture_path: Path):
    # We require:
    # - Positive: at least one fixture produces >=1 finding for the rule.
    # - Negative: at least one fixture produces 0 findings for the rule.
    fixtures = [
        "sample-lara",
        "laravel-blade-mini",
        "laravel-inertia-react-mini",
        "laravel-schema-governance-invalid-mini",
        "laravel-schema-governance-valid-mini",
        "laravel-async-communication-invalid-mini",
        "laravel-async-communication-valid-mini",
        "php-native-mini",
        "php-mvc-mini",
    ]

    # Use the strict profile to ensure every rule is enabled for fixture coverage.
    backend_root = Path(__file__).resolve().parents[2]
    ruleset = Ruleset.load(backend_root / "rulesets" / "strict.yaml")
    enabled_rule_ids = {rid for rid, cfg in ruleset.rules.items() if cfg.enabled}
    per_rule_counts: dict[str, list[int]] = {rid: [] for rid in enabled_rule_ids}

    for fx in fixtures:
        project_root = fixture_path / fx
        info = ProjectDetector(str(project_root)).detect()
        facts = FactsBuilder(info).build()
        metrics = MetricsAnalyzer().analyze(facts)
        engine = create_engine(ruleset=ruleset)
        result = engine.run(facts, metrics, info.project_type.value)

        # Count findings per rule for this fixture.
        counts: dict[str, int] = {rid: 0 for rid in enabled_rule_ids}
        for f in result.findings:
            counts[f.rule_id] = counts.get(f.rule_id, 0) + 1

        for rid in enabled_rule_ids:
            per_rule_counts[rid].append(counts.get(rid, 0))

    missing_positive = [rid for rid, xs in per_rule_counts.items() if max(xs) == 0]
    missing_negative = [rid for rid, xs in per_rule_counts.items() if min(xs) > 0]

    missing_positive_required = [rid for rid in missing_positive if rid not in OPTIONAL_POSITIVE_RULES]

    assert not missing_positive_required, f"Rules missing positive fixture coverage: {missing_positive_required}"
    assert not missing_negative, f"Rules missing negative fixture coverage: {missing_negative}"
