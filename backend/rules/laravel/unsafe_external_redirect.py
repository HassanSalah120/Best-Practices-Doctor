"""
Unsafe External Redirect Rule

Detects variable-driven external redirects without visible signed URL validation.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class UnsafeExternalRedirectRule(Rule):
    id = "unsafe-external-redirect"
    name = "Unsafe External Redirect"
    description = "Detects external redirects that appear to trust unvalidated input"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]
    regex_file_extensions = [".php"]

    _ALLOWLIST = ("/tests/", "/test/", "/vendor/", "/database/")
    _REDIRECT_PATTERNS = [
        re.compile(r"redirect\s*\(\s*\)\s*->\s*away\s*\(\s*(?P<expr>[^)\n]+?)\s*\)", re.IGNORECASE),
        re.compile(r"return\s+redirect\s*\(\s*(?P<expr>[^)\n]+?)\s*\)", re.IGNORECASE),
        re.compile(r"redirect\s*\(\s*\)\s*->\s*to\s*\(\s*(?P<expr>[^)\n]+?)\s*\)", re.IGNORECASE),
    ]
    _TRUSTED_URL_BUILDERS = (
        "route(",
        "to_route(",
        "url(",
        "secure_url(",
        "action(",
        "signedRoute(",
        "temporarySignedRoute(",
        "clinicUrl(",
        "tenantDomains->clinicUrl(",
    )
    _LOCAL_VALIDATION_SIGNALS = (
        "parse_url(",
        "filter_var(",
        "allowlist",
        "allowlisted",
        "allowed_hosts",
        "trusted_hosts",
        "trusted_domains",
        "isAllowedRedirectHost",
        "isSafeRedirectHost",
        "validateRedirectHost",
        "trustedredirector",
        "externalredirectvalidator",
        "redirectvalidator",
        "redirector",
        "validatedredirect",
        "safaredirect",
        "sanitize(",
        "isallowed(",
        "resolvedashboardurl",
        "resolvepayment",
        "resolvepaymentredirect",
        "resolveredirect",
        "validateandsanitizeredirecturl",
        "sanitizeredirecturl",
        "allowed_external_hosts",
        "initiatepayment->execute",
        "initiateinvoiceonlinepaymentaction",
    )
    _SIMPLE_VAR = re.compile(r"^\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)$")
    _METHOD_SIGNATURE = re.compile(
        r"function\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<params>[^)]*)\)",
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
        if any(marker in norm for marker in self._ALLOWLIST):
            return []
        text = content or ""

        for match, expr in self._iter_redirect_matches(text):
            if "$" not in expr:
                continue
            local_window, line = self._local_window(text, match.start())
            method_window = self._method_window(text, match.start())
            if self._is_trusted_redirect(expr, local_window, method_window, text):
                continue
            return [
                self.create_finding(
                    title="External redirect appears to use unvalidated input",
                    context=f"{file_path}:{line}:redirect",
                    file=file_path,
                    line_start=line,
                    description=(
                        "Detected a variable-driven external redirect (`redirect()->away(...)` or equivalent)"
                        " without a visible trusted URL builder or host allowlist check."
                    ),
                    why_it_matters=(
                        "Unvalidated external redirects can be abused for phishing, open redirect chains,"
                        " and tampering with tracked-link flows."
                    ),
                    suggested_fix=(
                        "Build redirect targets from trusted route/domain helpers, or validate the host against"
                        " an explicit allowlist before redirecting externally."
                    ),
                    tags=["laravel", "security", "redirect", "signed-urls"],
                    confidence=0.84,
                    evidence_signals=[
                        f"file={file_path}",
                        f"line={line}",
                        "variable_driven_external_redirect=true",
                        "trusted_builder_missing=true",
                    ],
                )
            ]
        return []

    def _iter_redirect_matches(self, text: str) -> list[tuple[re.Match[str], str]]:
        matches: list[tuple[re.Match[str], str]] = []
        for pat in self._REDIRECT_PATTERNS:
            for match in pat.finditer(text):
                expr = str(match.groupdict().get("expr") or "").strip()
                if expr:
                    matches.append((match, expr))
        matches.sort(key=lambda item: item[0].start())
        return matches

    def _local_window(self, text: str, start_idx: int, before: int = 30, after: int = 12) -> tuple[str, int]:
        lines = text.splitlines()
        line = text.count("\n", 0, start_idx) + 1
        start_line = max(0, line - before - 1)
        end_line = min(len(lines), line + after)
        return ("\n".join(lines[start_line:end_line]), line)

    def _method_window(self, text: str, start_idx: int) -> str:
        before = text.rfind("function", 0, start_idx)
        start = 0 if before == -1 else before
        after = text.find("\n    public function", start_idx)
        if after == -1:
            after = text.find("\n    protected function", start_idx)
        if after == -1:
            after = text.find("\n    private function", start_idx)
        if after == -1:
            after = len(text)
        return text[start:after]

    def _is_trusted_redirect(self, expr: str, local_window: str, method_window: str, full_text: str) -> bool:
        expr_low = expr.lower()
        window_low = local_window.lower()
        method_low = (method_window or "").lower()

        if any(builder.lower() in expr_low for builder in self._TRUSTED_URL_BUILDERS):
            return True
        if any(signal.lower() in expr_low for signal in self._LOCAL_VALIDATION_SIGNALS):
            return True

        var_name = self._extract_simple_var_name(expr)
        if var_name:
            # Track assignment/backflow chains for helper methods and sanitized variables.
            if self._has_trusted_assignment_chain(var_name, method_window):
                return True
            if self._has_trusted_parameter_backflow(var_name, method_window, full_text):
                return True

            for builder in self._TRUSTED_URL_BUILDERS:
                if re.search(
                    rf"\${re.escape(var_name)}\s*=\s*[^;\n]*{re.escape(builder)}",
                    local_window,
                    re.IGNORECASE,
                ):
                    return True
            for signal in self._LOCAL_VALIDATION_SIGNALS:
                if re.search(
                    rf"\${re.escape(var_name)}\b[^\n]*{re.escape(signal)}",
                    method_window,
                    re.IGNORECASE,
                ):
                    return True
            if re.search(
                rf"\${re.escape(var_name)}\s*=\s*[^;\n]*(resolve[a-z0-9_]*url|sanitize|trusted[a-z0-9_]*redirect|route\(|to_route\(|url\()",
                method_window,
                re.IGNORECASE,
            ):
                return True

        return any(signal.lower() in window_low or signal.lower() in method_low for signal in self._LOCAL_VALIDATION_SIGNALS)

    def _extract_simple_var_name(self, expr: str) -> str | None:
        match = self._SIMPLE_VAR.match(expr.strip())
        if not match:
            return None
        return str(match.group("name") or "")

    def _has_trusted_assignment_chain(self, var_name: str, method_window: str) -> bool:
        visited: set[str] = set()
        queue: list[str] = [var_name]
        steps = 0

        while queue and steps < 12:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            steps += 1

            for rhs in self._assignment_rhs_for_var(current, method_window):
                rhs_low = rhs.lower()
                if any(builder.lower() in rhs_low for builder in self._TRUSTED_URL_BUILDERS):
                    return True
                if any(signal.lower() in rhs_low for signal in self._LOCAL_VALIDATION_SIGNALS):
                    return True
                nested = self._extract_simple_var_name(rhs)
                if nested and nested not in visited:
                    queue.append(nested)
        return False

    def _assignment_rhs_for_var(self, var_name: str, method_window: str) -> list[str]:
        if not var_name or not method_window:
            return []
        out: list[str] = []
        pattern = re.compile(
            rf"\${re.escape(var_name)}\s*=\s*(?P<rhs>[^;\n]+)",
            re.IGNORECASE,
        )
        for match in pattern.finditer(method_window):
            rhs = str(match.groupdict().get("rhs") or "").strip()
            if rhs:
                out.append(rhs)
        return out

    def _has_trusted_parameter_backflow(self, var_name: str, method_window: str, full_text: str) -> bool:
        signature = self._METHOD_SIGNATURE.search(method_window or "")
        if not signature:
            return False
        method_name = str(signature.groupdict().get("name") or "").strip()
        params = str(signature.groupdict().get("params") or "")
        if not method_name:
            return False
        if not re.search(rf"\${re.escape(var_name)}\b", params):
            return False

        call_pattern = re.compile(
            rf"->\s*{re.escape(method_name)}\s*\((?P<args>[^)]*)\)",
            re.IGNORECASE,
        )
        for call in call_pattern.finditer(full_text or ""):
            args = str(call.groupdict().get("args") or "")
            args_low = args.lower()
            if any(builder.lower() in args_low for builder in self._TRUSTED_URL_BUILDERS):
                return True
            if any(signal.lower() in args_low for signal in self._LOCAL_VALIDATION_SIGNALS):
                return True
            for arg_var_match in re.finditer(r"\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)", args):
                arg_var = str(arg_var_match.groupdict().get("name") or "")
                if arg_var and self._has_trusted_assignment_chain(arg_var, full_text):
                    return True
        return False
