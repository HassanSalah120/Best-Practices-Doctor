"""Laravel Runtime Contract Guard analysis.

This module keeps the guard intentionally read-only. Static contract checks run
for every app route, and runtime probes are limited to safe local GET/HEAD
requests unless a future testing-environment flow explicitly enables mutations.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from schemas.facts import ClassInfo, Facts, MethodInfo, RouteInfo, ValidationUsage
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.report import GeneratedContractTest, RouteContractIssue, RuntimeContractSummary


MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SAFE_RUNTIME_METHODS = {"GET", "HEAD"}
APP_ROUTE_SKIP_PREFIXES = (
    "_debugbar",
    "_ignition",
    "horizon",
    "livewire",
    "nova",
    "sanctum/csrf-cookie",
    "storage",
    "telescope",
    "up",
    "vendor",
)
FRAMEWORK_CONTROLLER_PREFIXES = (
    "Illuminate\\",
    "Laravel\\",
    "Symfony\\",
    "Spatie\\",
    "Barryvdh\\",
)


@dataclass(frozen=True)
class RouteContract:
    route: RouteInfo
    controller_class: ClassInfo | None = None
    controller_method: MethodInfo | None = None
    accepted_fields: set[str] = field(default_factory=set)
    required_fields: set[str] = field(default_factory=set)
    request_used_fields: set[str] = field(default_factory=set)
    inertia_page: str | None = None
    inertia_props: set[str] = field(default_factory=set)
    page_required_props: set[str] = field(default_factory=set)


class RuntimeContractAnalyzer:
    """Analyze Laravel routes, request DTOs, Inertia payloads, and safe pages."""

    def __init__(self, *, runtime_timeout_seconds: float = 3.0):
        self.runtime_timeout_seconds = runtime_timeout_seconds
        self._file_cache: dict[str, str] = {}

    def analyze(
        self,
        *,
        facts: Facts,
        project_path: str,
        mode: str = "hybrid",
        scope: str = "all",
        base_url: str | None = None,
        allow_mutating_probes: bool = False,
        manual_routes: list[str] | None = None,
        changed_files: list[str] | None = None,
    ) -> tuple[RuntimeContractSummary, list[Finding]]:
        mode = self._normalize_mode(mode)
        scope = self._normalize_scope(scope)
        summary = RuntimeContractSummary(mode=mode, scope=scope)
        findings: list[Finding] = []

        if mode == "off":
            return summary, findings

        root = Path(project_path).resolve()
        routes, route_warning = self.load_routes(root, facts)
        if route_warning:
            summary.warnings.append(route_warning)

        routes = [route for route in routes if self._is_app_route(route)]
        routes = self._apply_scope(routes, scope, manual_routes or [], changed_files or [])
        summary.routes_total = len(routes)

        frontend_forms = self._collect_frontend_form_payloads(root, facts)
        route_contracts: list[RouteContract] = []
        for route in routes:
            contract, static_findings, static_issues = self._analyze_static_route(
                root,
                facts,
                route,
                frontend_forms=frontend_forms,
            )
            route_contracts.append(contract)
            summary.static_checked += 1
            findings.extend(static_findings)
            summary.issues.extend(static_issues)

        for contract in route_contracts:
            tests = self._tests_for_contract(contract, summary.issues)
            summary.generated_test_items.extend(tests)

        if mode == "hybrid":
            runtime_base_url = self._resolve_local_base_url(root, base_url)
            if runtime_base_url:
                self._run_safe_runtime_probes(
                    runtime_base_url,
                    route_contracts,
                    summary,
                    findings,
                    allow_mutating_probes=allow_mutating_probes,
                )
            else:
                summary.warnings.append(
                    "Runtime probes skipped because no confirmed local APP_URL/runtime_base_url was available."
                )
                summary.skipped["no_local_base_url"] = len(route_contracts)

        summary.generated_tests = len(summary.generated_test_items)
        return summary, findings

    def load_routes(self, root: Path, facts: Facts) -> tuple[list[RouteInfo], str | None]:
        """Prefer `php artisan route:list --json`, with static facts as fallback."""

        static_routes = list(getattr(facts, "routes", []) or [])
        artisan = root / "artisan"
        if not artisan.exists():
            return static_routes, None

        try:
            result = subprocess.run(
                ["php", "artisan", "route:list", "--json"],
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except Exception as exc:
            return static_routes, f"php artisan route:list --json could not run; static routes were used. {exc}"

        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip().splitlines()
            suffix = f" {detail[0]}" if detail else ""
            return static_routes, f"php artisan route:list --json failed; static routes were used.{suffix}"

        try:
            raw = json.loads(result.stdout or "[]")
        except json.JSONDecodeError as exc:
            return static_routes, f"php artisan route:list --json returned invalid JSON; static routes were used. {exc}"

        if not isinstance(raw, list):
            return static_routes, "php artisan route:list --json returned an unexpected shape; static routes were used."

        static_by_signature = self._static_route_signature_map(static_routes)
        imported: list[RouteInfo] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            methods = self._split_methods(str(item.get("method") or item.get("verb") or "GET"))
            uri = self._normalize_uri(str(item.get("uri") or ""))
            name = self._empty_to_none(item.get("name"))
            action_raw = str(item.get("action") or "").strip()
            controller, action = self._parse_artisan_action(action_raw)
            middleware = self._parse_middleware_payload(item.get("middleware"))
            for method in methods:
                static_match = static_by_signature.get((method, uri, name or "")) or static_by_signature.get(
                    (method, uri, "")
                )
                imported.append(
                    RouteInfo(
                        method=method,
                        uri=uri,
                        name=name,
                        controller=controller or getattr(static_match, "controller", None),
                        action=action or getattr(static_match, "action", None),
                        middleware=middleware or list(getattr(static_match, "middleware", []) or []),
                        file_path=str(getattr(static_match, "file_path", "") or ""),
                        line_number=int(getattr(static_match, "line_number", 0) or 0),
                        source="artisan",
                    )
                )

        return imported or static_routes, None

    def _analyze_static_route(
        self,
        root: Path,
        facts: Facts,
        route: RouteInfo,
        *,
        frontend_forms: dict[str, list[tuple[str, set[str]]]],
    ) -> tuple[RouteContract, list[Finding], list[RouteContractIssue]]:
        findings: list[Finding] = []
        issues: list[RouteContractIssue] = []

        controller_class = self._find_controller_class(facts, route.controller)
        controller_method = self._find_controller_method(facts, route, controller_class)
        contract = RouteContract(route=route, controller_class=controller_class, controller_method=controller_method)

        if route.controller and not self._is_closure_or_view_route(route):
            if controller_class is None:
                finding, issue = self._make_issue_and_finding(
                    kind="route_target",
                    route=route,
                    category=Category.ARCHITECTURE,
                    severity=Severity.HIGH,
                    title="Laravel route controller target cannot be resolved",
                    detail=f"{self._route_label(route)} references {route.controller}, but that controller was not found in the scanned app classes.",
                    suggested_fix="Update the route target or add the missing controller class before this route can be trusted at runtime.",
                    file=self._route_file(route),
                    line=self._route_line(route),
                    confidence=0.92,
                    metadata={"controller": route.controller, "action": route.action},
                )
                return contract, [finding], [issue]

            if controller_method is None:
                action = route.action or "__invoke"
                finding, issue = self._make_issue_and_finding(
                    kind="route_target",
                    route=route,
                    category=Category.ARCHITECTURE,
                    severity=Severity.HIGH,
                    title="Laravel route action method cannot be resolved",
                    detail=f"{self._route_label(route)} points at {route.controller}::{action}, but that method was not found.",
                    suggested_fix="Rename the route action, add the controller method, or convert the route to a valid invokable controller.",
                    file=getattr(controller_class, "file_path", "") or self._route_file(route),
                    line=self._route_line(route),
                    confidence=0.94,
                    metadata={"controller": route.controller, "action": action},
                )
                return contract, [finding], [issue]

        if controller_method is None:
            return contract, findings, issues

        source = self._method_source(root, controller_method)
        accepted, required = self._validation_contract_for_method(root, facts, controller_method, source)
        request_used = self._extract_request_used_fields(source)
        route_params = set(self._extract_route_params(route.uri))
        missing_validation = sorted(
            field
            for field in request_used
            if not self._field_is_satisfied(field, accepted)
            and not self._field_is_satisfied(field, route_params)
            and not self._is_low_signal_get_query(route, source, field)
        )

        contract = RouteContract(
            route=route,
            controller_class=controller_class,
            controller_method=controller_method,
            accepted_fields=accepted,
            required_fields=required,
            request_used_fields=request_used,
        )

        if missing_validation:
            finding, issue = self._make_issue_and_finding(
                kind="request_validation",
                route=route,
                category=Category.VALIDATION,
                severity=Severity.HIGH if self._is_mutating(route) else Severity.MEDIUM,
                title="Route reads request fields that are not in its validation contract",
                detail=(
                    f"{self._route_label(route)} uses request field(s) {', '.join(missing_validation)} "
                    "but they were not found in inline validation or a FormRequest rules() contract."
                ),
                suggested_fix="Add the missing fields to a FormRequest/inline validation contract, or stop reading unvalidated request data.",
                file=controller_method.file_path,
                line=int(controller_method.line_start or 1),
                confidence=0.82,
                metadata={
                    "missing_fields": missing_validation,
                    "accepted_fields": sorted(accepted),
                    "request_used_fields": sorted(request_used),
                },
            )
            findings.append(finding)
            issues.append(issue)

        dto_findings, dto_issues = self._analyze_dto_contracts(root, facts, route, controller_method, source, accepted)
        findings.extend(dto_findings)
        issues.extend(dto_issues)

        inertia_contract, inertia_findings, inertia_issues = self._analyze_inertia_contract(
            root,
            facts,
            route,
            controller_method,
            source,
            contract,
        )
        contract = inertia_contract
        findings.extend(inertia_findings)
        issues.extend(inertia_issues)

        frontend_findings, frontend_issues = self._analyze_frontend_form_contract(
            route,
            controller_method,
            accepted,
            required,
            frontend_forms,
        )
        findings.extend(frontend_findings)
        issues.extend(frontend_issues)

        binding_findings, binding_issues = self._analyze_route_model_binding(route, controller_method, source)
        findings.extend(binding_findings)
        issues.extend(binding_issues)

        return contract, findings, issues

    def _analyze_dto_contracts(
        self,
        root: Path,
        facts: Facts,
        route: RouteInfo,
        method: MethodInfo,
        source: str,
        accepted_fields: set[str],
    ) -> tuple[list[Finding], list[RouteContractIssue]]:
        findings: list[Finding] = []
        issues: list[RouteContractIssue] = []
        dto_classes = self._dto_class_index(facts)
        if not dto_classes:
            return findings, issues

        patterns = [
            r"new\s+([A-Z][A-Za-z0-9_\\]*(?:Dto|DTO|Data|Payload))\s*\((?P<args>.*?)\)",
            r"([A-Z][A-Za-z0-9_\\]*(?:Dto|DTO|Data|Payload))::(?:fromArray|fromRequest|make)\s*\((?P<args>.*?)\)",
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, source, flags=re.DOTALL):
                dto_name = match.group(1)
                dto_class = self._resolve_class_by_name(dto_classes, dto_name)
                if dto_class is None:
                    continue
                required = self._required_constructor_fields(root, dto_class)
                if not required:
                    continue

                args = match.group("args") or ""
                supplied = self._extract_named_arguments(args) or self._extract_php_array_keys(args)
                if not supplied:
                    if "fromrequest" in match.group(0).lower() or "validated" in args.lower() or "$request" in args:
                        supplied = set(accepted_fields)
                missing = sorted(field for field in required if not self._field_is_satisfied(field, supplied))
                if not missing:
                    continue

                finding, issue = self._make_issue_and_finding(
                    kind="dto_contract",
                    route=route,
                    category=Category.ARCHITECTURE,
                    severity=Severity.HIGH if self._is_mutating(route) else Severity.MEDIUM,
                    title="DTO required fields are not supplied by the route payload",
                    detail=(
                        f"{self._route_label(route)} builds {dto_class.name}, but required DTO field(s) "
                        f"{', '.join(missing)} are not present in the validated/supplied payload."
                    ),
                    suggested_fix="Pass the missing DTO fields from validated input, or make them nullable/defaulted in the DTO contract.",
                    file=method.file_path,
                    line=int(method.line_start or 1),
                    confidence=0.78,
                    metadata={
                        "dto": dto_class.fqcn,
                        "required_fields": sorted(required),
                        "supplied_fields": sorted(supplied),
                        "missing_fields": missing,
                    },
                )
                findings.append(finding)
                issues.append(issue)

        return findings, issues

    def _analyze_inertia_contract(
        self,
        root: Path,
        facts: Facts,
        route: RouteInfo,
        method: MethodInfo,
        source: str,
        contract: RouteContract,
    ) -> tuple[RouteContract, list[Finding], list[RouteContractIssue]]:
        findings: list[Finding] = []
        issues: list[RouteContractIssue] = []
        render_call = self._extract_inertia_render_call(source)
        if not render_call:
            return contract, findings, issues

        page, payload = render_call
        render_props = self._extract_php_array_keys(payload) | self._extract_compact_keys(payload)
        payload_is_unknown = bool(payload.strip()) and not render_props and not self._looks_like_empty_payload(payload)
        page_file = self._find_inertia_page_file(root, facts, page)
        if page_file is None:
            finding, issue = self._make_issue_and_finding(
                kind="inertia_page",
                route=route,
                category=Category.REACT_BEST_PRACTICE,
                severity=Severity.HIGH,
                title="Inertia page referenced by Laravel route was not found",
                detail=f"{self._route_label(route)} renders Inertia page '{page}', but no matching page file was found under resources/js/Pages.",
                suggested_fix="Create the page component or update Inertia::render() to the existing component path.",
                file=method.file_path,
                line=int(method.line_start or 1),
                confidence=0.9,
                metadata={"page": page},
            )
            findings.append(finding)
            issues.append(issue)
            return RouteContract(**{**contract.__dict__, "inertia_page": page, "inertia_props": render_props}), findings, issues

        page_source = self._read_file(root, page_file)
        required_props = self._extract_required_react_props(page_source)
        missing: list[str] = []
        if not payload_is_unknown:
            missing = sorted(prop for prop in required_props if prop not in render_props and prop not in {"children"})
        updated = RouteContract(
            route=contract.route,
            controller_class=contract.controller_class,
            controller_method=contract.controller_method,
            accepted_fields=contract.accepted_fields,
            required_fields=contract.required_fields,
            request_used_fields=contract.request_used_fields,
            inertia_page=page,
            inertia_props=render_props,
            page_required_props=required_props,
        )
        if missing:
            finding, issue = self._make_issue_and_finding(
                kind="inertia_props",
                route=route,
                category=Category.REACT_BEST_PRACTICE,
                severity=Severity.HIGH,
                title="Inertia page expects props that the route does not send",
                detail=(
                    f"{self._route_label(route)} renders '{page}' with prop(s) "
                    f"{', '.join(sorted(render_props) or ['<none>'])}, but the page requires {', '.join(missing)}."
                ),
                suggested_fix="Add the missing props to Inertia::render(), or make the React page props optional with a safe empty state.",
                file=method.file_path,
                line=int(method.line_start or 1),
                confidence=0.84,
                metadata={
                    "page": page,
                    "page_file": page_file,
                    "render_props": sorted(render_props),
                    "required_props": sorted(required_props),
                    "missing_props": missing,
                },
            )
            findings.append(finding)
            issues.append(issue)

        return updated, findings, issues

    def _analyze_frontend_form_contract(
        self,
        route: RouteInfo,
        method: MethodInfo,
        accepted_fields: set[str],
        required_fields: set[str],
        frontend_forms: dict[str, list[tuple[str, set[str]]]],
    ) -> tuple[list[Finding], list[RouteContractIssue]]:
        if not route.name or not self._is_mutating(route):
            return [], []
        form_payloads = frontend_forms.get(route.name) or []
        if not form_payloads or not required_fields:
            return [], []

        findings: list[Finding] = []
        issues: list[RouteContractIssue] = []
        for file_path, sent_fields in form_payloads:
            if not sent_fields:
                continue
            missing = sorted(field for field in required_fields if not self._field_is_satisfied(field, sent_fields))
            unexpected = sorted(field for field in sent_fields if accepted_fields and not self._field_is_satisfied(field, accepted_fields))
            if not missing and not unexpected:
                continue

            parts: list[str] = []
            if missing:
                parts.append(f"missing required field(s): {', '.join(missing)}")
            if unexpected:
                parts.append(f"sends unaccepted field(s): {', '.join(unexpected)}")
            finding, issue = self._make_issue_and_finding(
                kind="frontend_form_payload",
                route=route,
                category=Category.VALIDATION,
                severity=Severity.HIGH if missing else Severity.MEDIUM,
                title="Frontend form payload does not match the Laravel route contract",
                detail=f"{file_path} submits to route('{route.name}') but {', '.join(parts)}.",
                suggested_fix="Align the modal/form payload with the route validation contract, or update the FormRequest to accept the submitted fields.",
                file=file_path,
                line=1,
                confidence=0.76,
                metadata={
                    "route_name": route.name,
                    "required_fields": sorted(required_fields),
                    "accepted_fields": sorted(accepted_fields),
                    "sent_fields": sorted(sent_fields),
                    "missing_fields": missing,
                    "unexpected_fields": unexpected,
                },
            )
            findings.append(finding)
            issues.append(issue)
        return findings, issues

    def _analyze_route_model_binding(
        self,
        route: RouteInfo,
        method: MethodInfo,
        source: str = "",
    ) -> tuple[list[Finding], list[RouteContractIssue]]:
        params = set(self._extract_route_params(route.uri))
        if not params:
            return [], []
        method_param_vars = self._method_parameter_variables(method, source)
        missing = sorted(param for param in params if param not in method_param_vars and param.replace("-", "_") not in method_param_vars)
        if not missing:
            return [], []
        finding, issue = self._make_issue_and_finding(
            kind="route_model_binding",
            route=route,
            category=Category.ARCHITECTURE,
            severity=Severity.LOW,
            title="Route parameters are not visible in the controller action signature",
            detail=(
                f"{self._route_label(route)} declares route parameter(s) {', '.join(missing)}, "
                "but the controller action signature does not expose matching variables."
            ),
            suggested_fix="Confirm the parameter is intentionally unused, or add the scalar/model-bound parameter to the controller method signature.",
            file=method.file_path,
            line=int(method.line_start or 1),
            confidence=0.62,
            metadata={"route_params": sorted(params), "method_params": sorted(method_param_vars)},
        )
        return [finding], [issue]

    def _run_safe_runtime_probes(
        self,
        base_url: str,
        contracts: list[RouteContract],
        summary: RuntimeContractSummary,
        findings: list[Finding],
        *,
        allow_mutating_probes: bool,
    ) -> None:
        runtime_unavailable = False
        for contract in contracts:
            route = contract.route
            method = self._primary_method(route)
            if method in MUTATING_METHODS and not allow_mutating_probes:
                summary.skipped["mutating_generated_test_only"] = summary.skipped.get("mutating_generated_test_only", 0) + 1
                continue
            if method not in SAFE_RUNTIME_METHODS:
                summary.skipped["unsupported_method"] = summary.skipped.get("unsupported_method", 0) + 1
                continue
            if self._extract_route_params(route.uri):
                summary.skipped["dynamic_route_params"] = summary.skipped.get("dynamic_route_params", 0) + 1
                continue
            if self._route_needs_auth(route):
                summary.skipped["auth_required"] = summary.skipped.get("auth_required", 0) + 1
                continue
            if runtime_unavailable:
                summary.skipped["runtime_unavailable"] = summary.skipped.get("runtime_unavailable", 0) + 1
                continue

            url = self._route_url(base_url, route.uri)
            try:
                status, body = self._safe_http_get(url)
                summary.runtime_probed += 1
            except urllib.error.URLError as exc:
                runtime_unavailable = True
                summary.warnings.append(f"Runtime probes stopped because the local app was unreachable: {exc}")
                summary.skipped["runtime_unavailable"] = summary.skipped.get("runtime_unavailable", 0) + 1
                continue
            except Exception as exc:
                summary.warnings.append(f"Runtime probe skipped for {self._route_label(route)}: {exc}")
                summary.skipped["probe_error"] = summary.skipped.get("probe_error", 0) + 1
                continue

            if status in {401, 403}:
                summary.skipped["auth_or_forbidden"] = summary.skipped.get("auth_or_forbidden", 0) + 1
                continue
            if status < 500 and status != 404:
                continue

            severity = Severity.HIGH if status >= 500 else Severity.MEDIUM
            snippet = self._summarize_runtime_body(body)
            finding, issue = self._make_issue_and_finding(
                kind="runtime_probe",
                route=route,
                category=Category.LARAVEL_BEST_PRACTICE,
                severity=severity,
                title="Safe runtime route probe returned a failing response",
                detail=f"GET {url} returned HTTP {status}.{(' ' + snippet) if snippet else ''}",
                suggested_fix="Open the route locally, inspect the Laravel exception, and add a feature test that covers the failing contract.",
                file=self._route_file(route),
                line=self._route_line(route),
                confidence=0.95,
                metadata={"status": status, "url": url, "body_snippet": snippet},
            )
            findings.append(finding)
            summary.issues.append(issue)
            summary.generated_test_items.extend(self._tests_for_route_issue(contract, issue))

    def _validation_contract_for_method(
        self,
        root: Path,
        facts: Facts,
        method: MethodInfo,
        source: str,
    ) -> tuple[set[str], set[str]]:
        accepted: set[str] = set()
        required: set[str] = set()
        for validation in self._validations_for_method(facts, method):
            keys, req = self._fields_from_validation(validation)
            accepted.update(keys)
            required.update(req)

        for class_name in self._form_request_parameter_types(method, source):
            cls = self._find_class_by_short_or_fqcn(getattr(facts, "form_requests", []) or getattr(facts, "classes", []), class_name)
            if cls is None:
                continue
            keys, req = self._parse_form_request_rules(root, cls)
            accepted.update(keys)
            required.update(req)

        # When code explicitly uses validated() without extracted facts, infer keys
        # from nearby inline arrays as a safety net.
        inline_rules = self._extract_inline_validation_rules(source)
        for field, rules in inline_rules.items():
            accepted.add(field)
            if self._rules_include_confirmed(rules):
                accepted.add(f"{field}_confirmation")
            if self._rules_include_required(rules):
                required.add(field)

        return accepted, required

    def _validations_for_method(self, facts: Facts, method: MethodInfo) -> Iterable[ValidationUsage]:
        for validation in getattr(facts, "validations", []) or []:
            if self._normalize_rel_path(validation.file_path) != self._normalize_rel_path(method.file_path):
                continue
            if validation.method_name and validation.method_name != method.name:
                continue
            yield validation

    def _fields_from_validation(self, validation: ValidationUsage) -> tuple[set[str], set[str]]:
        accepted: set[str] = set()
        required: set[str] = set()
        for field, raw_rules in (validation.rules or {}).items():
            normalized = self._normalize_field(field)
            if not normalized:
                continue
            accepted.add(normalized)
            rules = [str(rule) for rule in (raw_rules or [])]
            if self._rules_include_required(rules):
                required.add(normalized)
            if self._rules_include_confirmed(rules):
                accepted.add(f"{normalized}_confirmation")
        return accepted, required

    def _parse_form_request_rules(self, root: Path, cls: ClassInfo) -> tuple[set[str], set[str]]:
        source = self._read_file(root, cls.file_path)
        rules_body = self._extract_method_body_by_name(source, "rules")
        rules = self._extract_validation_rule_map(rules_body or source)
        accepted = {self._normalize_field(field) for field in rules if self._normalize_field(field)}
        accepted.update(
            f"{self._normalize_field(field)}_confirmation"
            for field, raw_rules in rules.items()
            if self._normalize_field(field) and self._rules_include_confirmed(raw_rules)
        )
        required = {
            self._normalize_field(field)
            for field, raw_rules in rules.items()
            if self._normalize_field(field) and self._rules_include_required(raw_rules)
        }
        return accepted, required

    def _extract_inline_validation_rules(self, source: str) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for match in re.finditer(
            r"(?:->validate|Validator::make)\s*\((?P<body>[\s\S]*?\[[\s\S]*?\])\s*\)",
            source,
            flags=re.DOTALL,
        ):
            out.update(self._extract_validation_rule_map(match.group("body")))
        return out

    def _extract_validation_rule_map(self, source: str) -> dict[str, list[str]]:
        rules: dict[str, list[str]] = {}
        for match in re.finditer(
            r"['\"](?P<field>[A-Za-z0-9_.\-*]+)['\"]\s*=>\s*(?P<rules>\[[^\]]*\]|['\"][^'\"]*['\"]|[A-Za-z0-9_\\:|,\s]+)",
            source or "",
            flags=re.DOTALL,
        ):
            field = self._normalize_field(match.group("field"))
            if not field:
                continue
            raw = match.group("rules") or ""
            rule_names = re.findall(r"['\"]([^'\"]+)['\"]", raw)
            if not rule_names and "|" in raw:
                rule_names = [part.strip() for part in raw.strip("'\" ").split("|") if part.strip()]
            if not rule_names:
                rule_names = [raw.strip()]
            rules[field] = rule_names
        return rules

    def _extract_request_used_fields(self, source: str) -> set[str]:
        fields: set[str] = set()
        patterns = [
            r"\$request\s*->\s*(?:input|get|post|query|boolean|integer|string|date)\s*\(\s*['\"]([^'\"]+)['\"]",
            r"request\s*\(\s*['\"]([^'\"]+)['\"]",
            r"\$request\s*->\s*(?:validated|safe)\s*\(\s*['\"]([^'\"]+)['\"]",
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, source or "", flags=re.IGNORECASE):
                field = self._normalize_field(match.group(1))
                if field:
                    fields.add(field)

        for match in re.finditer(r"\$request\s*->\s*(?:only|except)\s*\((?P<body>.*?)\)", source or "", flags=re.DOTALL):
            fields.update(self._extract_string_list(match.group("body")))
        for match in re.finditer(r"\$request\s*->\s*safe\s*\(\s*\)\s*->\s*only\s*\((?P<body>.*?)\)", source or "", flags=re.DOTALL):
            fields.update(self._extract_string_list(match.group("body")))
        return fields

    def _collect_frontend_form_payloads(self, root: Path, facts: Facts) -> dict[str, list[tuple[str, set[str]]]]:
        by_route: dict[str, list[tuple[str, set[str]]]] = {}
        candidates = [
            path
            for path in (getattr(facts, "files", []) or [])
            if path.replace("\\", "/").endswith((".tsx", ".jsx", ".ts", ".js", ".vue"))
            and "/resources/js/" in f"/{path.replace('\\', '/')}"
        ]
        if not candidates:
            js_root = root / "resources" / "js"
            if js_root.exists():
                candidates = [p.relative_to(root).as_posix() for p in js_root.rglob("*") if p.suffix in {".tsx", ".jsx", ".ts", ".js", ".vue"}]

        for rel_path in candidates:
            source = self._read_file(root, rel_path)
            if "route(" not in source:
                continue
            form_defaults = self._collect_use_form_keys(source)
            for match in re.finditer(r"route\s*\(\s*['\"](?P<name>[^'\"]+)['\"]", source):
                route_name = match.group("name")
                window = source[max(0, match.start() - 600) : min(len(source), match.end() + 1000)]
                payloads = self._extract_js_payload_keys(window)
                if not payloads and form_defaults:
                    payloads = [form_defaults]
                for payload in payloads:
                    by_route.setdefault(route_name, []).append((rel_path, payload))
        return by_route

    def _collect_use_form_keys(self, source: str) -> set[str]:
        keys: set[str] = set()
        for match in re.finditer(r"useForm\s*(?:<[^>]+>)?\s*\(\s*\{(?P<body>[\s\S]*?)\}\s*\)", source or "", flags=re.DOTALL):
            keys.update(self._extract_js_object_keys(match.group("body")))
        return keys

    def _extract_js_payload_keys(self, source: str) -> list[set[str]]:
        out: list[set[str]] = []
        for match in re.finditer(
            r"(?:router|form|Inertia)\s*\.\s*(?:post|put|patch|delete|submit)\s*\([\s\S]*?,\s*\{(?P<body>[\s\S]*?)\}\s*(?:,|\))",
            source or "",
            flags=re.DOTALL,
        ):
            keys = self._extract_js_object_keys(match.group("body"))
            if keys:
                out.append(keys)
        return out

    def _tests_for_contract(
        self,
        contract: RouteContract,
        all_issues: list[RouteContractIssue],
    ) -> list[GeneratedContractTest]:
        tests: list[GeneratedContractTest] = []
        route = contract.route
        related = [
            issue
            for issue in all_issues
            if issue.route_method == self._primary_method(route)
            and issue.route_uri == self._normalize_uri(route.uri)
            and issue.route_name == route.name
        ]
        for issue in related:
            tests.extend(self._tests_for_route_issue(contract, issue))

        if self._is_mutating(route) and not any(test.route_uri == self._normalize_uri(route.uri) for test in tests):
            tests.append(
                self._build_feature_test(
                    route,
                    title=f"Generated contract test for {self._route_label(route)}",
                    reason="Mutating route was not probed against the real app; generated test only.",
                    issue_ids=[],
                    required_fields=contract.required_fields,
                    inertia_page=contract.inertia_page,
                    inertia_props=contract.page_required_props,
                    auth_required=self._route_needs_auth(route),
                )
            )
        return tests

    def _tests_for_route_issue(self, contract: RouteContract, issue: RouteContractIssue) -> list[GeneratedContractTest]:
        return [
            self._build_feature_test(
                contract.route,
                title=f"Contract regression test for {issue.title}",
                reason=issue.detail,
                issue_ids=[issue.id],
                required_fields=contract.required_fields,
                inertia_page=contract.inertia_page,
                inertia_props=contract.page_required_props,
                auth_required=self._route_needs_auth(contract.route),
            )
        ]

    def _build_feature_test(
        self,
        route: RouteInfo,
        *,
        title: str,
        reason: str,
        issue_ids: list[str],
        required_fields: set[str],
        inertia_page: str | None,
        inertia_props: set[str],
        auth_required: bool,
    ) -> GeneratedContractTest:
        method = self._primary_method(route).lower()
        uri = self._test_uri(route.uri)
        payload = self._sample_payload(required_fields)
        payload_php = self._php_array_literal(payload, indent="    ")
        test_name = self._pest_test_name(title, route)
        assertions: list[str] = []
        if auth_required:
            assertions.append("    $this->markTestSkipped('Add an authenticated test user/factory for this route middleware.');")
        if method in {"post", "put", "patch", "delete"} and required_fields:
            assertions.append(f"    $this->{method}('{uri}', [])->assertSessionHasErrors({self._php_string_list(sorted(required_fields))});")
        call_payload = f", {payload_php}" if payload else ""
        if method in {"post", "put", "patch", "delete"}:
            assertions.append(f"    $response = $this->{method}('{uri}'{call_payload});")
        else:
            assertions.append(f"    $response = $this->{method}('{uri}');")
        assertions.append("    $response->assertStatus(fn ($status) => $status < 500);")
        if inertia_page:
            assertions.append(f"    $response->assertInertia(fn ($page) => $page->component('{inertia_page}')")
            for prop in sorted(inertia_props):
                assertions.append(f"        ->has('{prop}')")
            assertions[-1] = assertions[-1] + ";"
        content = "\n".join(
            [
                "<?php",
                "",
                "use function Pest\\Laravel\\{get, post, put, patch, delete};",
                "",
                f"test('{test_name}', function () {{",
                *assertions,
                "});",
                "",
            ]
        )
        return GeneratedContractTest(
            id=f"contract_test_{self._short_hash(route.method + route.uri + title + reason)}",
            route_method=self._primary_method(route),
            route_uri=self._normalize_uri(route.uri),
            route_name=route.name,
            title=title,
            reason=reason,
            content=content,
            issue_ids=issue_ids,
        )

    def _make_issue_and_finding(
        self,
        *,
        kind: str,
        route: RouteInfo,
        category: Category,
        severity: Severity,
        title: str,
        detail: str,
        suggested_fix: str,
        file: str,
        line: int,
        confidence: float,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[Finding, RouteContractIssue]:
        method = self._primary_method(route)
        normalized_uri = self._normalize_uri(route.uri)
        context = f"{kind}:{method}:{normalized_uri}:{route.name or ''}:{route.controller or ''}:{route.action or ''}"
        finding = Finding(
            rule_id=f"runtime-{kind.replace('_', '-')}",
            context=context,
            title=title,
            category=category,
            severity=severity,
            classification=FindingClassification.DEFECT if severity in {Severity.CRITICAL, Severity.HIGH} else FindingClassification.RISK,
            file=self._normalize_rel_path(file) or self._route_file(route),
            line_start=max(1, int(line or 1)),
            line_end=max(1, int(line or 1)),
            description=detail,
            why_it_matters="This route can pass a static scan but still fail in Laravel when controller, request, DTO, or Inertia contracts drift.",
            suggested_fix=suggested_fix,
            score_impact=5 if severity in {Severity.CRITICAL, Severity.HIGH} else 2,
            tags=["runtime_contract", "laravel", kind],
            evidence_signals=[
                f"route={method} {normalized_uri}",
                f"controller={route.controller or 'none'}",
                f"action={route.action or 'none'}",
            ],
            metadata={
                "runtime_contract": True,
                "kind": kind,
                "route_method": method,
                "route_uri": normalized_uri,
                "route_name": route.name,
                "controller": route.controller,
                "action": route.action,
                **(metadata or {}),
            },
            confidence=confidence,
        )
        issue = RouteContractIssue(
            id=f"contract_issue_{finding.fingerprint}",
            kind=kind,
            severity=severity,
            category=category.value,
            route_method=method,
            route_uri=normalized_uri,
            route_name=route.name,
            controller=route.controller,
            action=route.action,
            file=finding.file,
            line=finding.line_start,
            title=title,
            detail=detail,
            finding_fingerprint=finding.fingerprint,
            metadata=dict(finding.metadata or {}),
        )
        return finding, issue

    def _find_controller_class(self, facts: Facts, controller: str | None) -> ClassInfo | None:
        if not controller:
            return None
        controller = self._normalize_fqcn(controller)
        classes = list(getattr(facts, "controllers", []) or []) + list(getattr(facts, "classes", []) or [])
        return self._find_class_by_short_or_fqcn(classes, controller)

    def _find_controller_method(self, facts: Facts, route: RouteInfo, cls: ClassInfo | None) -> MethodInfo | None:
        if cls is None:
            return None
        action = route.action or "__invoke"
        for method in getattr(facts, "methods", []) or []:
            if method.name != action:
                continue
            method_cls = self._normalize_fqcn(method.class_fqcn or method.class_name)
            if method_cls == self._normalize_fqcn(cls.fqcn) or method.class_name == cls.name:
                return method
        return None

    def _find_class_by_short_or_fqcn(self, classes: Iterable[ClassInfo], name: str | None) -> ClassInfo | None:
        if not name:
            return None
        target = self._normalize_fqcn(name)
        target_short = target.split("\\")[-1]
        for cls in classes:
            if self._normalize_fqcn(cls.fqcn) == target:
                return cls
        for cls in classes:
            if cls.name == target_short or self._normalize_fqcn(cls.fqcn).endswith("\\" + target_short):
                return cls
        return None

    def _resolve_class_by_name(self, class_index: dict[str, ClassInfo], name: str) -> ClassInfo | None:
        normalized = self._normalize_fqcn(name)
        if normalized in class_index:
            return class_index[normalized]
        return class_index.get(normalized.split("\\")[-1])

    def _dto_class_index(self, facts: Facts) -> dict[str, ClassInfo]:
        out: dict[str, ClassInfo] = {}
        for cls in getattr(facts, "classes", []) or []:
            if not re.search(r"(Dto|DTO|Data|Payload)$", cls.name):
                continue
            out[self._normalize_fqcn(cls.fqcn)] = cls
            out[cls.name] = cls
        return out

    def _required_constructor_fields(self, root: Path, cls: ClassInfo) -> set[str]:
        source = self._read_file(root, cls.file_path)
        match = re.search(r"function\s+__construct\s*\((?P<params>[\s\S]*?)\)\s*(?::[^{]+)?\{", source, flags=re.DOTALL)
        if not match:
            return set()
        fields: set[str] = set()
        for raw_param in self._split_args(match.group("params")):
            if "=" in raw_param:
                continue
            if "?" in raw_param.split("$")[0]:
                continue
            m = re.search(r"\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)", raw_param)
            if m:
                fields.add(self._normalize_field(m.group("name")))
        return fields

    def _method_source(self, root: Path, method: MethodInfo) -> str:
        source = self._read_file(root, method.file_path)
        lines = source.splitlines()
        start = max(1, int(method.line_start or 1)) - 1
        end = int(method.line_end or method.line_start or len(lines))
        return "\n".join(lines[start:end]) if lines else source

    def _read_file(self, root: Path, rel_path: str) -> str:
        rel_path = str(rel_path or "")
        if rel_path in self._file_cache:
            return self._file_cache[rel_path]
        path = Path(rel_path)
        full_path = path if path.is_absolute() else root / rel_path
        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            content = ""
        self._file_cache[rel_path] = content
        return content

    def _extract_method_body_by_name(self, source: str, method_name: str) -> str:
        pattern = r"function\s+{}\s*\([^)]*\)\s*(?::[^{{]+)?\{{".format(re.escape(method_name))
        match = re.search(pattern, source, flags=re.DOTALL)
        if not match:
            return ""
        start = match.end()
        depth = 1
        idx = start
        while idx < len(source):
            char = source[idx]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return source[start:idx]
            idx += 1
        return source[start:]

    def _form_request_parameter_types(self, method: MethodInfo, source: str) -> set[str]:
        out: set[str] = set()
        raw_params = " ".join(str(param) for param in (method.parameters or []))
        signature = source.split("{", 1)[0] if source else raw_params
        for haystack in {raw_params, signature}:
            for match in re.finditer(r"(?P<type>[A-Za-z_\\][A-Za-z0-9_\\]*)\s+\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)", haystack):
                type_name = match.group("type").split("|")[-1].strip("\\")
                short = type_name.split("\\")[-1]
                if short == "Request" or not short.endswith("Request"):
                    continue
                out.add(type_name)
        return out

    def _method_parameter_variables(self, method: MethodInfo, source: str = "") -> set[str]:
        out: set[str] = set()
        params = [str(param or "") for param in (method.parameters or [])]
        if source:
            signature_match = re.search(
                rf"function\s+{re.escape(str(method.name or ''))}\s*\((?P<params>[\s\S]*?)\)",
                source,
                flags=re.DOTALL,
            )
            if signature_match:
                params.extend(self._split_args(signature_match.group("params")))
            else:
                signature = source.split("{", 1)[0]
                params.extend(
                    self._split_args(signature[signature.find("(") + 1 : signature.rfind(")")])
                    if "(" in signature and ")" in signature
                    else []
                )
        for param in params:
            match = re.search(r"\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)", str(param))
            if match:
                out.add(match.group("name"))
            elif re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", str(param)):
                out.add(str(param))
        return out

    def _extract_inertia_render_call(self, source: str) -> tuple[str, str] | None:
        match = re.search(r"Inertia::render\s*\(", source or "")
        if not match:
            return None

        open_index = match.end() - 1
        args_body = self._balanced_body(source, open_index)
        if args_body is None:
            return None
        args = self._split_args(args_body)
        if not args:
            return None

        page_match = re.match(r"\s*['\"]([^'\"]+)['\"]", args[0])
        if not page_match:
            return None
        return page_match.group(1), args[1] if len(args) > 1 else ""

    def _balanced_body(self, source: str, open_index: int) -> str | None:
        if open_index < 0 or open_index >= len(source) or source[open_index] != "(":
            return None
        depth = 1
        quote: str | None = None
        escape = False
        idx = open_index + 1
        while idx < len(source):
            char = source[idx]
            if quote:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == quote:
                    quote = None
                idx += 1
                continue
            if char in {"'", '"'}:
                quote = char
                idx += 1
                continue
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return source[open_index + 1 : idx]
            idx += 1
        return None

    def _looks_like_empty_payload(self, payload: str) -> bool:
        return payload.strip().replace(" ", "") in {"[]", "array()"}

    def _find_inertia_page_file(self, root: Path, facts: Facts, page: str) -> str | None:
        normalized = page.strip("/").replace("\\", "/")
        candidates = [
            f"resources/js/Pages/{normalized}.{ext}"
            for ext in ("tsx", "jsx", "ts", "js", "vue")
        ] + [
            f"resources/js/Pages/{normalized}/Index.{ext}"
            for ext in ("tsx", "jsx", "ts", "js", "vue")
        ]
        files = {self._normalize_rel_path(path) for path in (getattr(facts, "files", []) or [])}
        for candidate in candidates:
            if candidate in files or (root / candidate).exists():
                return candidate
        lower_files = {path.lower(): path for path in files}
        for candidate in candidates:
            found = lower_files.get(candidate.lower())
            if found:
                return found
        return None

    def _extract_required_react_props(self, source: str) -> set[str]:
        typed_props: set[str] = set()
        for match in re.finditer(r"(?:interface|type)\s+\w*Props\s*(?:=\s*)?\{(?P<body>[\s\S]*?)\}", source or "", flags=re.DOTALL):
            body = match.group("body")
            for prop in re.finditer(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(\?)?\s*:", body, flags=re.MULTILINE):
                if prop.group(2) != "?":
                    typed_props.add(prop.group(1))
        if typed_props:
            return typed_props

        props: set[str] = set()
        for match in re.finditer(r"(?:function\s+\w+|const\s+\w+\s*=\s*\(|export\s+default\s+function\s*\w*)\s*\(\s*\{(?P<body>[^}]*)\}", source or "", flags=re.DOTALL):
            for part in self._split_args(match.group("body")):
                name = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:[:=,]|$)", part)
                if not name:
                    continue
                prop_name = name.group(1)
                if prop_name not in {"className", "children"}:
                    props.add(prop_name)
        return props

    def _extract_php_array_keys(self, source: str) -> set[str]:
        return {
            self._normalize_field(match.group(1))
            for match in re.finditer(r"['\"]([A-Za-z0-9_.\-*]+)['\"]\s*=>", source or "")
            if self._normalize_field(match.group(1))
        }

    def _extract_compact_keys(self, source: str) -> set[str]:
        keys: set[str] = set()
        for match in re.finditer(r"compact\s*\((?P<body>.*?)\)", source or "", flags=re.DOTALL):
            keys.update(self._extract_string_list(match.group("body")))
        return keys

    def _extract_named_arguments(self, source: str) -> set[str]:
        return {
            self._normalize_field(match.group(1))
            for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*:", source or "")
            if self._normalize_field(match.group(1))
        }

    def _extract_string_list(self, source: str) -> set[str]:
        return {
            self._normalize_field(match.group(1))
            for match in re.finditer(r"['\"]([A-Za-z0-9_.\-*]+)['\"]", source or "")
            if self._normalize_field(match.group(1))
        }

    def _extract_js_object_keys(self, source: str) -> set[str]:
        keys: set[str] = set()
        for match in re.finditer(r"(?:^|[,{\s])([A-Za-z_][A-Za-z0-9_]*)\s*:", source or ""):
            key = self._normalize_field(match.group(1))
            if key:
                keys.add(key)
        for match in re.finditer(r"['\"]([A-Za-z0-9_.\-]+)['\"]\s*:", source or ""):
            key = self._normalize_field(match.group(1))
            if key:
                keys.add(key)
        return keys

    def _split_args(self, source: str) -> list[str]:
        args: list[str] = []
        current: list[str] = []
        depth = 0
        quote: str | None = None
        escape = False
        for char in source or "":
            if quote:
                current.append(char)
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == quote:
                    quote = None
                continue
            if char in {"'", '"'}:
                quote = char
                current.append(char)
                continue
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth = max(0, depth - 1)
            if char == "," and depth == 0:
                args.append("".join(current).strip())
                current = []
            else:
                current.append(char)
        if current:
            args.append("".join(current).strip())
        return args

    def _rules_include_required(self, rules: Iterable[str]) -> bool:
        text = "|".join(str(rule).lower() for rule in rules)
        return "required" in text and "nullable" not in text and "sometimes" not in text

    def _rules_include_confirmed(self, rules: Iterable[str]) -> bool:
        parts: list[str] = []
        for rule in rules:
            parts.extend(part.strip().lower() for part in str(rule).split("|"))
        return "confirmed" in parts

    def _field_is_satisfied(self, field: str, candidates: set[str]) -> bool:
        normalized = self._normalize_field(field)
        if not normalized:
            return True
        normalized_candidates = {self._normalize_field(candidate) for candidate in candidates}
        if normalized in normalized_candidates:
            return True
        base = normalized.split(".", 1)[0]
        return base in normalized_candidates

    def _normalize_field(self, field: str | None) -> str:
        field = str(field or "").strip().strip("'\"")
        field = field.replace(".*", "")
        return field.split(".", 1)[0].strip()

    def _normalize_fqcn(self, value: str | None) -> str:
        return str(value or "").strip().strip("\\").replace("/", "\\")

    def _normalize_rel_path(self, path: str | None) -> str:
        return str(path or "").replace("\\", "/").lstrip("./")

    def _normalize_uri(self, uri: str) -> str:
        return str(uri or "").strip().strip("/")

    def _primary_method(self, route: RouteInfo) -> str:
        methods = self._split_methods(route.method)
        return next((method for method in methods if method != "HEAD"), methods[0] if methods else "GET")

    def _split_methods(self, raw: str) -> list[str]:
        methods = [part.strip().upper() for part in re.split(r"[|,]", str(raw or "GET")) if part.strip()]
        if "GET" in methods and "HEAD" in methods:
            methods = [method for method in methods if method != "HEAD"]
        return methods or ["GET"]

    def _parse_artisan_action(self, action: str) -> tuple[str | None, str | None]:
        if not action or action.lower() in {"closure", "view"}:
            return None, None
        action = action.replace("@", "::")
        if "::" in action:
            controller, method = action.rsplit("::", 1)
            return self._normalize_fqcn(controller), method or None
        if "\\" in action:
            return self._normalize_fqcn(action), "__invoke"
        return None, None

    def _parse_middleware_payload(self, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return [part.strip() for part in re.split(r"[,|]", str(value)) if part.strip()]

    def _static_route_signature_map(self, routes: list[RouteInfo]) -> dict[tuple[str, str, str], RouteInfo]:
        out: dict[tuple[str, str, str], RouteInfo] = {}
        for route in routes:
            for method in self._split_methods(route.method):
                out[(method, self._normalize_uri(route.uri), route.name or "")] = route
        return out

    def _empty_to_none(self, value: Any) -> str | None:
        text = str(value or "").strip()
        return text or None

    def _is_app_route(self, route: RouteInfo) -> bool:
        uri = self._normalize_uri(route.uri).lower()
        if any(uri == prefix or uri.startswith(prefix + "/") for prefix in APP_ROUTE_SKIP_PREFIXES):
            return False
        file_path = self._normalize_rel_path(route.file_path).lower()
        if "/vendor/" in f"/{file_path}" or file_path.startswith("vendor/"):
            return False
        controller = self._normalize_fqcn(route.controller)
        if controller and controller.startswith(FRAMEWORK_CONTROLLER_PREFIXES):
            return False
        return True

    def _apply_scope(
        self,
        routes: list[RouteInfo],
        scope: str,
        manual_routes: list[str],
        changed_files: list[str],
    ) -> list[RouteInfo]:
        if scope == "manual":
            needles = {item.strip().strip("/") for item in manual_routes if item.strip()}
            if not needles:
                return []
            return [
                route
                for route in routes
                if self._normalize_uri(route.uri) in needles
                or (route.name or "") in needles
                or self._route_label(route) in needles
            ]
        if scope == "changed_critical" and changed_files:
            changed = {self._normalize_rel_path(path) for path in changed_files}
            return [
                route
                for route in routes
                if self._normalize_rel_path(route.file_path) in changed
                or self._is_mutating(route)
                or "auth" in " ".join(route.middleware).lower()
            ]
        return routes

    def _normalize_mode(self, mode: str | None) -> str:
        mode = str(mode or "hybrid").strip().lower()
        return mode if mode in {"off", "static", "hybrid"} else "hybrid"

    def _normalize_scope(self, scope: str | None) -> str:
        scope = str(scope or "all").strip().lower()
        return scope if scope in {"all", "changed_critical", "manual"} else "all"

    def _is_closure_or_view_route(self, route: RouteInfo) -> bool:
        controller = str(route.controller or "").lower()
        action = str(route.action or "").lower()
        return controller in {"closure", "view"} or action in {"closure", "view"}

    def _route_label(self, route: RouteInfo) -> str:
        return f"{self._primary_method(route)} /{self._normalize_uri(route.uri)}"

    def _route_file(self, route: RouteInfo) -> str:
        return self._normalize_rel_path(route.file_path) or "routes/web.php"

    def _route_line(self, route: RouteInfo) -> int:
        return max(1, int(getattr(route, "line_number", 0) or 1))

    def _is_mutating(self, route: RouteInfo) -> bool:
        return self._primary_method(route) in MUTATING_METHODS

    def _route_needs_auth(self, route: RouteInfo) -> bool:
        middleware = " ".join(route.middleware or []).lower()
        uri = self._normalize_uri(route.uri).lower()
        return "auth" in middleware or uri.startswith("admin") or "/admin/" in f"/{uri}/"

    def _extract_route_params(self, uri: str) -> list[str]:
        return [
            match.group(1).rstrip("?")
            for match in re.finditer(r"\{([A-Za-z_][A-Za-z0-9_\-]*\??)\}", uri or "")
        ]

    def _is_low_signal_get_query(self, route: RouteInfo, source: str, field: str) -> bool:
        if self._primary_method(route) != "GET":
            return False
        needle = f"query('{field}'"
        return needle in source or f'query("{field}"' in source

    def _resolve_local_base_url(self, root: Path, explicit: str | None) -> str | None:
        candidates = [explicit] if explicit else []
        env_path = root / ".env"
        if env_path.exists():
            try:
                for line in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.strip().startswith("APP_URL="):
                        candidates.append(line.split("=", 1)[1].strip().strip('"\''))
                        break
            except Exception:
                pass
        for candidate in candidates:
            candidate = str(candidate or "").strip().rstrip("/")
            if not candidate:
                continue
            parsed = urllib.parse.urlparse(candidate)
            if parsed.scheme not in {"http", "https"}:
                continue
            host = (parsed.hostname or "").lower()
            if host in {"localhost", "127.0.0.1", "::1"}:
                return candidate
        return None

    def _route_url(self, base_url: str, uri: str) -> str:
        return base_url.rstrip("/") + "/" + self._normalize_uri(uri)

    def _safe_http_get(self, url: str) -> tuple[int, str]:
        request = urllib.request.Request(url, method="GET", headers={"Accept": "text/html,application/json"})
        try:
            with urllib.request.urlopen(request, timeout=self.runtime_timeout_seconds) as response:
                body = response.read(4096).decode("utf-8", errors="replace")
                return int(response.status), body
        except urllib.error.HTTPError as exc:
            body = exc.read(4096).decode("utf-8", errors="replace")
            return int(exc.code), body

    def _summarize_runtime_body(self, body: str) -> str:
        text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body or "")).strip()
        return text[:220]

    def _sample_payload(self, required_fields: set[str]) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        for field in sorted(required_fields):
            lower = field.lower()
            if "email" in lower:
                payload[field] = "runtime-contract@example.test"
            elif lower.startswith("is_") or lower.startswith("has_") or lower in {"active", "enabled"}:
                payload[field] = True
            elif lower.endswith("_id") or "count" in lower or "amount" in lower or "number" in lower:
                payload[field] = 1
            elif "date" in lower:
                payload[field] = "2026-01-01"
            elif lower.endswith("s"):
                payload[field] = []
            else:
                payload[field] = "sample"
        return payload

    def _php_array_literal(self, payload: dict[str, Any], *, indent: str = "") -> str:
        if not payload:
            return "[]"
        inner: list[str] = ["["]
        for key, value in payload.items():
            inner.append(f"{indent}    '{key}' => {self._php_value(value)},")
        inner.append(f"{indent}]")
        return "\n".join(inner)

    def _php_value(self, value: Any) -> str:
        if value is True:
            return "true"
        if value is False:
            return "false"
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, list):
            return "[]"
        escaped = str(value).replace("\\", "\\\\").replace("'", "\\'")
        return f"'{escaped}'"

    def _php_string_list(self, values: list[str]) -> str:
        return "[" + ", ".join("'" + value.replace("'", "\\'") + "'" for value in values) + "]"

    def _test_uri(self, uri: str) -> str:
        normalized = "/" + self._normalize_uri(uri)
        normalized = re.sub(r"\{[A-Za-z_][A-Za-z0-9_\-]*\?\}", "", normalized)
        normalized = re.sub(r"\{[A-Za-z_][A-Za-z0-9_\-]*\}", "1", normalized)
        return normalized or "/"

    def _pest_test_name(self, title: str, route: RouteInfo) -> str:
        text = f"{self._route_label(route)} {title}".lower()
        text = re.sub(r"[^a-z0-9 /:_-]+", "", text)
        return text[:140].replace("'", "")

    def _short_hash(self, text: str) -> str:
        return hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()[:12]
