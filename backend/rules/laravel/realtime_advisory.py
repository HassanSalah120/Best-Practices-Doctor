"""Advisory rules for Laravel projects with standalone realtime/WebSocket runtimes."""
from __future__ import annotations

import re
from pathlib import Path

from rules.base import Rule
from schemas.facts import Facts, RouteInfo
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics

_MUTATING_METHODS = {"post", "put", "patch", "delete", "any", "match"}
_REALTIME_HINTS = (
    "workerman/workerman",
    "websocket/server.php",
    "connectioninterface",
    "socketmessagehandler",
    "realtime\\\\",
    "realtime\\",
)


def _norm(path: str) -> str:
    return str(path or "").replace("\\", "/").lstrip("./").lower()


class _RealtimeAdvisoryRule(Rule):
    default_classification = FindingClassification.ADVISORY
    type = "ast"
    detection_type = "cross-file"
    analysis_cost = "medium"
    auto_fixable = False
    confidence = "high"
    priority = 4
    applies_to = ["global"]
    references: list[str] = []
    related_rules: list[str] = []

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def _project_root(self, facts: Facts) -> Path:
        return Path(getattr(facts, "project_path", "") or ".")

    def _files(self, facts: Facts) -> list[str]:
        return [_norm(path) for path in (getattr(facts, "files", []) or [])]

    def _read(self, facts: Facts, rel_path: str) -> str:
        normalized = _norm(rel_path)
        original_path = next(
            (
                str(path or "").replace("\\", "/")
                for path in (getattr(facts, "files", []) or [])
                if _norm(path) == normalized
            ),
            rel_path,
        )
        try:
            return (self._project_root(facts) / original_path).read_text(encoding="utf-8", errors="replace")
        except Exception:
            return ""

    def _read_any(self, facts: Facts, rel_paths: list[str]) -> str:
        chunks: list[str] = []
        for rel in rel_paths:
            text = self._read(facts, rel)
            if text:
                chunks.append(text)
        return "\n".join(chunks)

    def _realtime_evidence(self, facts: Facts) -> list[str]:
        files = self._files(facts)
        evidence: list[str] = []

        if "websocket/server.php" in files:
            evidence.append("websocket_server=websocket/server.php")

        composer = self._read(facts, "composer.json")
        if composer:
            low = composer.lower()
            if "workerman/workerman" in low:
                evidence.append("composer=workerman/workerman")
            if "realtime\\\\" in low or "realtime\\" in low:
                evidence.append("autoload=Realtime")

        likely_files = [
            path
            for path in files
            if path.endswith(".php")
            and not any(
                path.startswith(prefix)
                for prefix in ("vendor/", "node_modules/", "storage/", ".git/", ".github/", "public/", "tests/")
            )
        ]
        text = self._read_any(facts, likely_files[:80]).lower()
        if "connectioninterface" in text:
            evidence.append("api=ConnectionInterface")
        if "socketmessagehandler" in text:
            evidence.append("handler=SocketMessageHandler")

        return list(dict.fromkeys(evidence))

    def _is_realtime_project(self, facts: Facts) -> bool:
        if self._realtime_evidence(facts):
            return True
        haystack = " ".join(self._files(facts)).lower()
        return any(hint in haystack for hint in _REALTIME_HINTS)

    def _line_for_file(self, facts: Facts, rel_path: str, pattern: str) -> int:
        text = self._read(facts, rel_path)
        if not text:
            return 1
        needle = pattern.lower()
        for idx, line in enumerate(text.splitlines(), start=1):
            if needle in line.lower():
                return idx
        return 1


class RealtimeInMemoryStateScalabilityRule(_RealtimeAdvisoryRule):
    id = "realtime-inmemory-state-scalability"
    name = "Realtime In-Memory State Scalability"
    description = "Detects standalone realtime runtimes that keep active room/player state only in process memory"
    category = Category.PERFORMANCE
    default_severity = Severity.LOW
    severity_weight = 2
    confidence = "high"
    fix_suggestion = (
        "For horizontal scaling, introduce a shared active-state adapter such as Redis for room, player, "
        "or connection coordination. Keep single-node in-memory state when that is the intended deployment model."
    )
    examples = {
        "bad": "private array $rooms = [];",
        "good": "final class RedisRoomConnectionRepository implements RoomConnectionRepositoryInterface { ... }",
    }
    priority = 4
    group = "Performance"
    applies_to = ["global"]
    references = []
    related_rules = []
    false_positive_notes = (
        "Single-node realtime apps may intentionally keep active connection state in memory. "
        "Do not treat this as a defect unless the project needs multi-node scaling or restart-resilient active sessions."
    )
    detection_type = "cross-file"
    analysis_cost = "medium"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "performance", "concern": "realtime-scalability"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if not self._is_realtime_project(facts):
            return []
        state_file = self._inmemory_state_file(facts)
        if not state_file or self._has_shared_state_adapter(facts):
            return []
        if self._has_intentional_single_node_documentation(facts, state_file):
            return []

        evidence = self._realtime_evidence(facts)
        evidence.extend(["active_state=in_memory", "shared_state_adapter_missing=true"])
        return [
            self.create_finding(
                title="Realtime state is single-process only",
                file=state_file,
                line_start=self._line_for_file(facts, state_file, "private array"),
                description=(
                    "The realtime runtime appears to keep active room/player/connection state in PHP process memory "
                    "without a Redis or shared-state adapter."
                ),
                why_it_matters=(
                    "This is fine for an intentional single-node deployment, but horizontal scaling or process restarts can lose active "
                    "connection coordination unless state is shared outside the worker process."
                ),
                suggested_fix=self.fix_suggestion,
                context="realtime:active-state",
                confidence=0.9,
                classification=FindingClassification.ADVISORY,
                tags=["laravel", "realtime", "websocket", "scalability"],
                evidence_signals=evidence,
                metadata={"advisory_lane": "realtime", "score_intent": "light"},
            ),
        ]

    def _inmemory_state_file(self, facts: Facts) -> str | None:
        for rel in self._files(facts):
            if not rel.endswith(".php") or not rel.startswith("websocket/"):
                continue
            text = self._read(facts, rel)
            if re.search(r"private\s+array\s+\$(rooms|players|connections|sessions|clients)\s*=\s*\[\s*\]", text, re.I):
                return rel
            if re.search(r"\$(rooms|players|connections|sessions|clients)\s*\[[^\]]+\]\s*(?:\?\?=|=)", text, re.I):
                return rel
            if "SplObjectStorage" in text:
                return rel
        return None

    def _has_shared_state_adapter(self, facts: Facts) -> bool:
        for rel in self._files(facts):
            if not rel.endswith(".php") or not rel.startswith("websocket/"):
                continue
            text = self._read(facts, rel)
            if re.search(r"\b(Redis|Predis|Cache::|cache\(|redis\()", text):
                return True
            if re.search(r"class\s+\w*(Redis|Shared|Distributed)\w*(Repository|Store|Adapter)", text):
                return True
        return False

    def _has_intentional_single_node_documentation(self, facts: Facts, rel_path: str) -> bool:
        text = self._read(facts, rel_path)
        if not text:
            return False

        lowered = text.lower()
        before_class = lowered.split("class ", 1)[0]
        has_intent = any(
            token in before_class
            for token in (
                "intentional",
                "architectural choice",
                "single-node deployment",
                "single node deployment",
                "single-process",
                "single process",
            )
        )
        has_connection_resource_context = any(
            token in lowered
            for token in (
                "tcpconnection",
                "connection resource",
                "live php resource",
                "workerman process",
                "process-bound",
                "process bound",
            )
        )
        has_future_scaling_context = any(
            token in lowered
            for token in (
                "future horizontal scaling",
                "shared active-state adapter",
                "redis",
                "pub/sub",
                "multiple nodes",
            )
        )
        return has_intent and has_connection_resource_context and has_future_scaling_context


class WebSocketHandlerIntegrationTestsMissingRule(_RealtimeAdvisoryRule):
    id = "websocket-handler-integration-tests-missing"
    name = "WebSocket Handler Integration Tests Missing"
    description = "Detects realtime handlers without handler-level or socket-message integration tests"
    category = Category.MAINTAINABILITY
    default_severity = Severity.LOW
    severity_weight = 2
    confidence = "high"
    fix_suggestion = (
        "Add a handler-level integration test that sends representative socket messages through the WebSocket "
        "message handler and verifies outgoing responses or broadcasts."
    )
    examples = {"good": "SocketMessageHandlerTest verifies join/spin/round message handling end to end."}
    priority = 4
    group = "Testing"
    applies_to = ["test", "php-class"]
    references = []
    related_rules = ["tests-missing"]
    false_positive_notes = (
        "May be satisfied by external smoke tests, browser E2E tests, or infrastructure-level WebSocket checks "
        "that are not visible in this repository."
    )
    detection_type = "cross-file"
    analysis_cost = "medium"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "testing", "concern": "websocket-tests"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if not self._is_realtime_project(facts) or not self._has_socket_handler(facts):
            return []
        if self._has_handler_integration_test(facts):
            return []

        anchor = self._handler_file(facts) or "websocket/server.php"
        evidence = self._realtime_evidence(facts)
        evidence.extend(
            [
                f"test_files_count={int(getattr(facts, 'test_files_count', 0) or 0)}",
                "handler_integration_test_missing=true",
            ],
        )
        return [
            self.create_finding(
                title="WebSocket handler lacks integration-style tests",
                file=anchor,
                line_start=self._line_for_file(facts, anchor, "SocketMessageHandler"),
                description=(
                    "The project has a realtime socket handler, but no test appears to exercise handler-level "
                    "socket message flow."
                ),
                why_it_matters=(
                    "Domain service tests are valuable, but handler tests catch message-shape, connection, "
                    "routing, and broadcast regressions at the realtime boundary."
                ),
                suggested_fix=self.fix_suggestion,
                context="realtime:handler-tests",
                confidence=0.88,
                classification=FindingClassification.ADVISORY,
                tags=["laravel", "realtime", "websocket", "testing"],
                evidence_signals=evidence,
                metadata={"advisory_lane": "realtime", "score_intent": "light"},
            ),
        ]

    def _has_socket_handler(self, facts: Facts) -> bool:
        return self._handler_file(facts) is not None

    def _handler_file(self, facts: Facts) -> str | None:
        for rel in self._files(facts):
            if rel.endswith(".php") and ("socketmessagehandler" in rel or "websocket" in rel and rel.endswith("server.php")):
                return rel
        return None

    def _has_handler_integration_test(self, facts: Facts) -> bool:
        for rel in self._files(facts) + self._filesystem_test_files(facts):
            if not rel.endswith(".php") or "/test" not in f"/{rel}":
                continue
            name = Path(rel).name.lower()
            text = self._read(facts, rel).lower()
            if any(token in name for token in ("socketmessagehandler", "websocket", "realtime", "socket")):
                return True
            if "socketmessagehandler" in text or ("connectioninterface" in text and "message" in text):
                return True
        return False

    def _filesystem_test_files(self, facts: Facts) -> list[str]:
        root = self._project_root(facts)
        tests_dir = root / "tests"
        if not tests_dir.exists():
            return []
        out: list[str] = []
        try:
            for path in tests_dir.rglob("*.php"):
                try:
                    rel = path.relative_to(root)
                except Exception:
                    continue
                out.append(_norm(str(rel)))
        except Exception:
            return []
        return out


class RealtimeConfigOutsideLaravelConfigRule(_RealtimeAdvisoryRule):
    id = "realtime-config-outside-laravel-config"
    name = "Realtime Config Outside Laravel Config"
    description = "Detects standalone realtime config files that are not bridged into Laravel config"
    category = Category.ARCHITECTURE
    default_severity = Severity.LOW
    severity_weight = 2
    confidence = "high"
    fix_suggestion = (
        "Move realtime settings into Laravel config or add a small bridge class that reads from config/*.php "
        "so HTTP and WebSocket runtimes share one configuration boundary."
    )
    examples = {
        "bad": "websocket/game_config.php is required directly by the socket server.",
        "good": "config/services.php contains websocket settings and App\\Support\\GameConfig exposes them.",
    }
    priority = 4
    group = "Architecture Integrity"
    applies_to = ["config"]
    references = []
    related_rules = ["env-outside-config"]
    false_positive_notes = (
        "Do not flag projects that already bridge standalone config through Laravel config files or a support class."
    )
    detection_type = "cross-file"
    analysis_cost = "medium"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "architecture", "concern": "realtime-config"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if not self._is_realtime_project(facts):
            return []
        config_file = self._standalone_config_file(facts)
        if not config_file or self._has_laravel_config_bridge(facts):
            return []

        evidence = self._realtime_evidence(facts)
        evidence.extend([f"standalone_config={config_file}", "laravel_config_bridge_missing=true"])
        return [
            self.create_finding(
                title="Realtime config is outside Laravel config",
                file=config_file,
                line_start=1,
                description=(
                    "A standalone realtime config file was detected without a Laravel config bridge."
                ),
                why_it_matters=(
                    "Separate configuration boundaries drift easily between HTTP and WebSocket runtimes."
                ),
                suggested_fix=self.fix_suggestion,
                context="realtime:config-bridge",
                confidence=0.86,
                classification=FindingClassification.ADVISORY,
                tags=["laravel", "realtime", "configuration"],
                evidence_signals=evidence,
                metadata={"advisory_lane": "realtime", "score_intent": "light"},
            ),
        ]

    def _standalone_config_file(self, facts: Facts) -> str | None:
        for rel in self._files(facts):
            if rel.startswith("websocket/") and rel.endswith(".php") and "config" in Path(rel).name:
                return rel
        return None

    def _has_laravel_config_bridge(self, facts: Facts) -> bool:
        files = self._files(facts)
        config_text = self._read_any(facts, [p for p in files if p.endswith(".php") and (p.startswith("config/") or "/config/" in p.lower())])
        has_websocket_config = bool(re.search(r"['\"\\]websocket['\"\\]|['\"\\]realtime['\"\\]", config_text, re.I))
        has_support_bridge = any(
            "/support/" in p.lower() and p.endswith(".php") and ("config" in p or "game" in p or "websocket" in p)
            for p in files
        )
        if has_websocket_config and has_support_bridge:
            return True

        app_text = self._read_any(facts, [p for p in files if p.endswith(".php") and not p.startswith(("vendor/", "node_modules/", "storage/", ".git/", ".github/", "public/", "tests/"))])
        return bool(has_websocket_config and re.search(r"config\s*\(\s*['\"\\](services|websocket|realtime)\.", app_text))


class PublicAnonymousMutationAbuseReadinessRule(_RealtimeAdvisoryRule):
    id = "public-anonymous-mutation-abuse-readiness"
    name = "Public Anonymous Mutation Abuse Readiness"
    description = "Reviews anonymous public game/room mutation endpoints for abuse controls"
    category = Category.SECURITY
    default_severity = Severity.MEDIUM
    severity_weight = 5
    confidence = "high"
    fix_suggestion = (
        "Keep CSRF and route throttling in place. For higher abuse pressure, add a pre-signed join token, "
        "captcha/challenge, or stronger room creation quota."
    )
    examples = {
        "bad": "Route::post('/rooms', [RoomController::class, 'store']);",
        "good": "Route::post('/rooms', ...)->middleware(['throttle:rooms']);",
    }
    priority = 4
    group = "Security Hardening"
    applies_to = ["route", "middleware"]
    references = ["OWASP A04:2021 - Insecure Design"]
    related_rules = ["missing-rate-limiting", "missing-csrf-token-verification"]
    false_positive_notes = (
        "Anonymous play/demo flows can intentionally expose public mutating endpoints. Existing CSRF, throttling, "
        "signed tokens, captcha, or upstream bot controls may be sufficient."
    )
    detection_type = "cross-file"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "security", "concern": "anonymous-mutation-abuse"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        candidates = [route for route in getattr(facts, "routes", []) or [] if self._is_public_realtime_mutation(route)]
        if not candidates:
            return []

        findings: list[Finding] = []
        for route in candidates:
            throttle_names = self._throttle_names(facts, route)
            has_throttle = bool(throttle_names) or self._has_middleware(route, ("throttle", "rate", "limiter"))
            has_csrf = self._has_middleware(route, ("csrf",)) or self._web_route_has_csrf(facts, route)
            has_token_control = self._has_middleware(
                route,
                ("signed", "signature", "captcha", "turnstile", "internal-key", "api-key", "ip-restrict", "allowlist"),
            )
            has_configured_named_limiter = any(self._named_rate_limiter_is_configured(facts, name) for name in throttle_names)
            if has_configured_named_limiter and (has_csrf or has_token_control):
                continue
            if has_throttle and (has_csrf or has_token_control):
                severity = Severity.LOW
                confidence = 0.82
                desc = (
                    "This anonymous mutating realtime endpoint has baseline abuse controls. Review whether a "
                    "pre-signed join token or challenge is needed only if abuse pressure increases."
                )
                evidence = ["baseline_controls_present=true"]
            else:
                severity = Severity.MEDIUM
                confidence = 0.88
                desc = (
                    "This anonymous mutating realtime endpoint appears to lack one or more baseline abuse controls "
                    "such as route throttling, CSRF/signed tokens, or bot challenges."
                )
                evidence = ["baseline_controls_incomplete=true"]

            evidence.extend(
                [
                    f"method={str(route.method or '').upper()}",
                    f"uri={route.uri}",
                    f"throttle={int(has_throttle)}",
                    f"named_rate_limiter={int(has_configured_named_limiter)}",
                    f"csrf_or_token={int(has_csrf or has_token_control)}",
                ],
            )
            findings.append(
                self.create_finding(
                    title="Anonymous realtime mutation endpoint should be abuse-ready",
                    file=route.file_path,
                    line_start=int(getattr(route, "line_number", 1) or 1),
                    description=desc,
                    why_it_matters=(
                        "Anonymous room/game creation and join flows are useful product choices, but they are "
                        "easy targets for automated abuse if baseline controls are missing or traffic grows."
                    ),
                    suggested_fix=self.fix_suggestion,
                    context=f"{str(route.method or '').upper()} {route.uri}",
                    severity=severity,
                    confidence=confidence,
                    classification=FindingClassification.ADVISORY,
                    tags=["laravel", "realtime", "anonymous-flow", "abuse-readiness"],
                    evidence_signals=evidence,
                    metadata={"advisory_lane": "realtime", "score_intent": "light"},
                ),
            )
        return findings

    def _is_public_realtime_mutation(self, route: RouteInfo) -> bool:
        if not self._is_mutating(route):
            return False
        if self._has_middleware(route, ("auth", "sanctum", "verified", "can:", "policy")):
            return False
        uri = str(route.uri or "").strip("/").lower()
        controller = str(route.controller or "").lower()
        return bool(
            re.search(r"(^|/)(room|rooms|game|games|join|restore|session|sessions)(/|$)", uri)
            or any(token in controller for token in ("room", "game", "socket", "realtime")),
        )

    def _is_mutating(self, route: RouteInfo) -> bool:
        method = str(route.method or "").strip().lower()
        parts = re.split(r"[|,\s]+", method)
        return any(part in _MUTATING_METHODS for part in parts)

    def _has_middleware(self, route: RouteInfo, tokens: tuple[str, ...]) -> bool:
        payload = " ".join(str(item or "").lower() for item in (route.middleware or []))
        return any(token in payload for token in tokens)

    def _throttle_names(self, facts: Facts, route: RouteInfo) -> list[str]:
        names: list[str] = []
        for item in route.middleware or []:
            text = str(item or "").strip()
            match = re.search(r"throttle\s*:\s*([A-Za-z0-9_.-]+)", text, re.I)
            if match:
                names.append(match.group(1))
        # Route extractors cannot always attach middleware inherited from a
        # fluent group.  Recover named throttles from the route's local source
        # context instead of assuming one particular routes directory.
        source = self._read(facts, str(route.file_path or ""))
        if source:
            lines = source.splitlines()
            line = max(1, int(getattr(route, "line_number", 1) or 1))
            window = "\n".join(lines[max(0, line - 18) : min(len(lines), line + 5)])
            for match in re.finditer(r"throttle\s*:\s*([A-Za-z0-9_.-]+)", window, re.I):
                names.append(match.group(1))
        return list(dict.fromkeys(names))

    def _named_rate_limiter_is_configured(self, facts: Facts, name: str) -> bool:
        if not name:
            return False
        escaped = re.escape(name)
        candidates = [
            path
            for path in self._files(facts)
            if path.endswith(".php")
            and not path.startswith(("vendor/", "tests/", "storage/", "node_modules/"))
        ]
        for path in candidates:
            source = self._read(facts, path)
            if not source or not re.search(rf"RateLimiter::for\s*\(\s*['\"]{escaped}['\"]", source):
                continue
            if re.search(r"\bLimit::per(?:Minute|Second|Hour|Day)\s*\(", source):
                return True
        return False

    def _web_route_has_csrf(self, facts: Facts, route: RouteInfo) -> bool:
        from rules.laravel._route_helpers import is_web_route_file
        if not is_web_route_file(route):
            return False
        kernel = self._read(facts, "app/Http/Kernel.php") or self._read(facts, "src/Http/Kernel.php")
        return "VerifyCsrfToken" in kernel or "verifycsrftoken" in kernel.lower()
