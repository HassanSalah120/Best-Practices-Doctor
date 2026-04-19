"""
SSRF Risk In HTTP Client Rule

Detects outbound HTTP calls using request-derived URLs without obvious allowlisting.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class SsrfRiskHttpClientRule(Rule):
    id = "ssrf-risk-http-client"
    name = "Potential SSRF in HTTP Client Call"
    description = "Detects request-derived URLs used in outbound HTTP calls without allowlist validation"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".php"]

    _ALLOWLIST_PATH_MARKERS = ("/tests/", "/test/", "/vendor/")
    _URL_VAR_FROM_REQUEST = re.compile(
        r"\$(?P<var>[a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(?:\$request->(?:input|query|get|post|route)\s*\(|request\(\)\s*->(?:input|query|get|post|route)\s*\(|\$_(?:GET|POST|REQUEST)\s*\[)",
        re.IGNORECASE,
    )
    _HTTP_CLIENT_CALL = re.compile(
        r"(?:Http::(?:withToken|withHeaders|timeout|retry|acceptJson|baseUrl)\s*\([^;]*?\)\s*->\s*)?"
        r"(?:Http::|->)(?:get|post|put|patch|delete|send|request)\s*\(\s*\$(?P<var>[a-zA-Z_][a-zA-Z0-9_]*)",
        re.IGNORECASE,
    )
    _DIRECT_REQUEST_URL_CALL = re.compile(
        r"(?:Http::|->)(?:get|post|put|patch|delete|send|request)\s*\(\s*(?:\$request->(?:input|query|get|post|route)\s*\(|request\(\)\s*->(?:input|query|get|post|route)\s*\()",
        re.IGNORECASE,
    )
    _SAFE_VALIDATION_SIGNALS = (
        "parse_url(",
        "filter_var(",
        "in_array(",
        "str_starts_with(",
        "startswith(",
        "isallowedhost(",
        "isallowedurl(",
        "trustedredirector",
        "allowlist",
        "whitelist",
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
        text = content or ""
        low_path = str(file_path or "").lower().replace("\\", "/")
        if any(marker in low_path for marker in self._ALLOWLIST_PATH_MARKERS):
            return []
        if "http::" not in text.lower() and "->request(" not in text.lower():
            return []

        require_external_integrations = bool(self.get_threshold("require_external_integrations_capability", False))
        if require_external_integrations and not self._capability_enabled(facts, "external_integrations_heavy"):
            return []

        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        findings: list[Finding] = []

        direct_match = self._DIRECT_REQUEST_URL_CALL.search(text)
        if direct_match:
            line = text.count("\n", 0, direct_match.start()) + 1
            confidence = 0.9
            if confidence + 1e-9 >= min_confidence:
                findings.append(
                    self.create_finding(
                        title="Outbound HTTP call uses request input as URL",
                        context="direct-request-url-http-call",
                        file=file_path,
                        line_start=line,
                        description="Detected an outbound HTTP call where URL is read directly from request input.",
                        why_it_matters=(
                            "User-controlled outbound URLs can lead to SSRF, including access to internal services and cloud metadata endpoints."
                        ),
                        suggested_fix=(
                            "Build outbound targets from trusted config/route maps, or enforce strict host allowlisting before making the request."
                        ),
                        confidence=confidence,
                        tags=["laravel", "security", "ssrf", "http-client"],
                        evidence_signals=["url_source=request_input", "http_client_call=detected"],
                        metadata={
                            "decision_profile": {
                                "decision": "emit",
                                "decision_summary": "request-derived URL used directly in outbound HTTP client call.",
                                "require_external_integrations_capability": require_external_integrations,
                            }
                        },
                    )
                )
            return findings

        request_vars: dict[str, int] = {}
        for match in self._URL_VAR_FROM_REQUEST.finditer(text):
            request_vars[str(match.group("var") or "").strip()] = match.start()
        if not request_vars:
            return []

        safe_low = text.lower()
        for call in self._HTTP_CLIENT_CALL.finditer(text):
            var_name = str(call.group("var") or "").strip()
            if not var_name or var_name not in request_vars:
                continue
            line = text.count("\n", 0, call.start()) + 1
            window_start = max(0, request_vars[var_name] - 500)
            window_end = min(len(text), call.end() + 600)
            window_low = text[window_start:window_end].lower()
            if any(signal in window_low for signal in self._SAFE_VALIDATION_SIGNALS):
                continue
            confidence = 0.86
            if confidence + 1e-9 < min_confidence:
                continue
            findings.append(
                self.create_finding(
                    title="Potential SSRF via request-derived URL variable",
                    context=f"url_var={var_name}",
                    file=file_path,
                    line_start=line,
                    description=(
                        f"Detected outbound HTTP call using `${var_name}` assigned from request input without obvious allowlist validation."
                    ),
                    why_it_matters=(
                        "Request-driven outbound URLs can be abused to probe internal endpoints or cloud metadata services."
                    ),
                    suggested_fix=(
                        "Validate scheme/host against explicit allowlists and reject private/internal IP ranges before sending requests."
                    ),
                    confidence=confidence,
                    tags=["laravel", "security", "ssrf", "http-client"],
                    evidence_signals=[f"url_var={var_name}", "url_source=request_input", "allowlist_signal=false"],
                    metadata={
                        "decision_profile": {
                            "decision": "emit",
                            "decision_summary": "request-derived URL variable reaches outbound HTTP client call.",
                            "url_var": var_name,
                            "require_external_integrations_capability": require_external_integrations,
                        }
                    },
                )
            )
            if findings:
                break

        return findings

    def _capability_enabled(self, facts: Facts, key: str) -> bool:
        project_context = getattr(facts, "project_context", None)
        capabilities = getattr(project_context, "capabilities", {}) if project_context else {}
        payload = capabilities.get(key) if isinstance(capabilities, dict) else None
        return bool(isinstance(payload, dict) and payload.get("enabled"))
