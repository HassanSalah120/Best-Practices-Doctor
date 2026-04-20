"""
Client-side auth-only authorization rule.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


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
            if not self._AUTH_GUARD.search(line):
                continue
            window = "\n".join(lines[max(0, i - 6):min(len(lines), i + 6)])
            if self._SERVER_SIGNAL.search(window):
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
                )
            )
        return findings
