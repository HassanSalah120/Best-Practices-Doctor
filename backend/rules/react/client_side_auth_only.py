"""
Client-side auth-only authorization rule.
"""

from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts, RouteInfo
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class ClientSideAuthOnlyRule(Rule):
    id = "client-side-auth-only"
    name = "Client-Side Authorization Only"
    description = "Detects UI authorization checks that appear to lack nearby server-side enforcement cues"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".tsx", ".ts", ".jsx", ".js"]

    _AUTH_GUARD = re.compile(
        r"\b(isAdmin|hasRole|canAccess|isOwner|isSuperuser)\b\s*(\?|&&)",
        re.IGNORECASE,
    )
    _SERVER_SIGNAL = re.compile(
        r"(usePage\(\)\.props|permissions|authorize|policy|middleware|server|backend|api/)",
        re.IGNORECASE,
    )
    _STRING_ONLY_TERNARY = re.compile(
        r"\b(?:isAdmin|hasRole|canAccess|isOwner|isSuperuser)\b\s*\?\s*(['\"][^'\"]+['\"])\s*:\s*(['\"][^'\"]+['\"])",
        re.IGNORECASE,
    )
    _DANGEROUS_UI_SIGNAL = re.compile(
        r"\b(?:onClick|fetch\s*\(|axios\.|router\.(?:post|put|patch|delete)|method=['\"](?:post|put|patch|delete)['\"]|"
        r"Delete|Remove|Destroy|Ban|Approve|Reject|Impersonate|Refund)\b",
        re.IGNORECASE,
    )
    _JSX_TAG = re.compile(r"<\s*([A-Za-z][A-Za-z0-9_.]*)\b")
    _SAFE_UI_TAGS = {
        "a",
        "badge",
        "div",
        "fragment",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "icon",
        "img",
        "label",
        "li",
        "link",
        "navlink",
        "p",
        "section",
        "small",
        "span",
        "strong",
        "tooltip",
        "ul",
    }
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Remove the client-side authorization only risk and enforce the relevant Laravel/React security control at the boundary. Add a regression test that proves unsafe input or configuration is rejected.'
    examples = {}
    priority = 1
    group = 'Access Control'
    applies_to = ['react-component']
    references = ['OWASP A07:2021 - Identification and Authentication Failures', 'CWE-287']
    related_rules = []
    false_positive_notes = 'May be a false positive when protection is enforced by upstream middleware, shared policy, or infrastructure not visible to the scanner.'
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'security', 'concern': 'client-side-auth'}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        norm = (file_path or "").replace("\\", "/").lower()
        if "/tests/" in norm or "/test/" in norm or norm.endswith(".test.tsx") or norm.endswith(".spec.tsx"):
            return []

        findings: list[Finding] = []
        lines = (content or "").splitlines()
        for i, line in enumerate(lines, start=1):
            guard_match = self._AUTH_GUARD.search(line)
            if not guard_match:
                continue
            window = "\n".join(lines[max(0, i - 6):min(len(lines), i + 6)])
            if self._SERVER_SIGNAL.search(window):
                continue
            if self._has_matching_backend_authorization(guard_match.group(1), window, facts):
                continue
            if self._is_presentation_only_gate(line, window):
                continue
            findings.append(
                self.create_finding(
                    title="Authorization appears enforced only on the client",
                    context=line.strip()[:120],
                    file=file_path,
                    line_start=i,
                    description=(
                        "Detected role/ownership gating in JSX without nearby evidence of server-side authorization enforcement."
                    ),
                    why_it_matters=(
                        "Client-only checks can be bypassed; sensitive actions must be authorized on the server."
                    ),
                    suggested_fix="Ensure matching backend authorization (policy/middleware/endpoint checks) for gated actions.",
                    confidence=0.84,
                    tags=["react", "security", "authorization", "frontend"],
                    evidence_signals=["client_only_auth_guard=true"],
                ),
            )
        return findings

    def _is_presentation_only_gate(self, line: str, window: str) -> bool:
        text = window or line or ""
        if self._STRING_ONLY_TERNARY.search(line or ""):
            return True
        if self._DANGEROUS_UI_SIGNAL.search(text):
            return False

        tags = {match.group(1).split(".")[-1].lower() for match in self._JSX_TAG.finditer(text)}
        if not tags:
            return False
        if not tags.issubset(self._SAFE_UI_TAGS):
            return False

        return bool(
            re.search(r"\b(?:to|href)\s*=", text)
            or re.search(r"\b(?:badge|role|label|display|avatar|menu|nav)\b", text, re.IGNORECASE),
        )

    def _has_matching_backend_authorization(self, guard_name: str, window: str, facts: Facts) -> bool:
        guard = (guard_name or "").strip().lower()
        target_path = self._extract_navigation_target(window)

        if guard == "isadmin":
            return self._has_authorized_route_for_target(target_path, facts.routes, required={"admin"})

        return False

    def _extract_navigation_target(self, text: str) -> str:
        match = re.search(r"\b(?:to|href)\s*=\s*(?:['\"](?P<literal>[^'\"]+)['\"]|\{[`'\"](?P<expr>[^`'\"]+)[`'\"]\})", text or "")
        if not match:
            return ""
        return str(match.group("literal") or match.group("expr") or "").strip()

    def _has_authorized_route_for_target(
        self,
        target_path: str,
        routes: list[RouteInfo],
        required: set[str],
    ) -> bool:
        normalized_target = "/" + (target_path or "").strip().strip("/")
        if normalized_target == "/":
            return False

        for route in routes:
            uri = "/" + (route.uri or "").strip().strip("/")
            route_prefix = uri.split("{", 1)[0].rstrip("/") or uri
            if not (
                normalized_target == route_prefix
                or normalized_target.startswith(route_prefix + "/")
                or route_prefix.startswith(normalized_target + "/")
            ):
                continue

            middleware = {str(m).lower().split(":", 1)[0] for m in route.middleware or []}
            if required.issubset(middleware) and ({"auth", "auth:sanctum"} & {str(m).lower() for m in route.middleware or []} or "auth" in middleware):
                return True

        return False
