from __future__ import annotations

from pathlib import Path

from core.ruleset import Ruleset
from rules.laravel.realtime_advisory import (
    PublicAnonymousMutationAbuseReadinessRule,
    RealtimeConfigOutsideLaravelConfigRule,
    RealtimeInMemoryStateScalabilityRule,
    WebSocketHandlerIntegrationTestsMissingRule,
)
from schemas.facts import Facts, RouteInfo
from schemas.finding import FindingClassification, Severity

REALTIME_COMPOSER = r'''{
  "require": {"workerman/workerman": "^5.1"},
  "autoload": {"psr-4": {"Realtime\\\\": "websocket/src/"}}
}'''


def _write(root: Path, rel: str, content: str) -> None:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def _facts(root: Path, routes: list[RouteInfo] | None = None) -> Facts:
    files = [
        str(path.relative_to(root)).replace("\\", "/")
        for path in root.rglob("*")
        if path.is_file()
    ]
    test_count = len([path for path in files if path.startswith("tests/") and path.endswith(".php")])
    return Facts(
        project_path=str(root),
        files=files,
        has_tests=test_count > 0,
        test_files_count=test_count,
        routes=routes or [],
    )


def _realtime_project(root: Path, repository: str = "") -> None:
    _write(root, "composer.json", REALTIME_COMPOSER)
    _write(
        root,
        "websocket/server.php",
        """<?php
use Workerman\\Worker;
use Workerman\\Connection\\ConnectionInterface;
use Realtime\\Services\\SocketMessageHandler;
$worker = new Worker('websocket://0.0.0.0:8080');
""",
    )
    _write(
        root,
        "websocket/src/Services/SocketMessageHandler.php",
        "<?php namespace Realtime\\Services; final class SocketMessageHandler {}",
    )
    if repository:
        _write(root, "websocket/src/Repositories/RoomConnectionRepository.php", repository)


def test_realtime_inmemory_state_scalability_flags_process_local_state(tmp_path: Path):
    _realtime_project(
        tmp_path,
        """<?php
namespace Realtime\\Repositories;
class RoomConnectionRepository {
    private array $rooms = [];
    public function add(string $room, $connection): void { $this->rooms[$room][] = $connection; }
}
""",
    )

    findings = RealtimeInMemoryStateScalabilityRule().analyze(_facts(tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "realtime-inmemory-state-scalability"
    assert findings[0].classification is FindingClassification.ADVISORY
    assert findings[0].severity is Severity.LOW


def test_realtime_inmemory_state_scalability_skips_redis_or_shared_adapter(tmp_path: Path):
    _realtime_project(
        tmp_path,
        """<?php
namespace Realtime\\Repositories;
use Illuminate\\Support\\Facades\\Redis;
class RedisRoomConnectionRepository {
    public function add(string $room, $connection): void { Redis::hset('rooms', $room, '1'); }
}
""",
    )

    findings = RealtimeInMemoryStateScalabilityRule().analyze(_facts(tmp_path))

    assert findings == []


def test_realtime_inmemory_state_scalability_skips_documented_single_node_tcp_connections(tmp_path: Path):
    _realtime_project(
        tmp_path,
        """<?php
namespace Realtime\\Repositories;
use Workerman\\Connection\\TcpConnection;

/**
 * Manages active WebSocket connections in memory.
 *
 * NOTE: This implementation uses single-process in-memory state, which is an intentional
 * architectural choice for the current single-node deployment model.
 *
 * TcpConnection objects are live PHP resources owned by the Workerman process, so
 * they cannot be serialized into Redis. For future horizontal scaling, a shared
 * active-state adapter and Pub/Sub coordination layer can be introduced.
 */
class RoomConnectionRepository {
    private array $rooms = [];
    public function add(string $room, TcpConnection $connection): void { $this->rooms[$room][] = $connection; }
}
""",
    )

    findings = RealtimeInMemoryStateScalabilityRule().analyze(_facts(tmp_path))

    assert findings == []


def test_realtime_inmemory_state_scalability_skips_non_realtime_arrays(tmp_path: Path):
    _write(tmp_path, "app/Services/PlainService.php", "<?php class PlainService { private array $rooms = []; }")

    findings = RealtimeInMemoryStateScalabilityRule().analyze(_facts(tmp_path))

    assert findings == []


def test_websocket_handler_integration_tests_missing_flags_domain_only_tests(tmp_path: Path):
    _realtime_project(tmp_path)
    _write(tmp_path, "tests/Unit/GameRoundServiceTest.php", "<?php class GameRoundServiceTest {}")

    findings = WebSocketHandlerIntegrationTestsMissingRule().analyze(_facts(tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "websocket-handler-integration-tests-missing"
    assert findings[0].classification is FindingClassification.ADVISORY
    assert findings[0].severity is Severity.LOW


def test_websocket_handler_integration_tests_missing_accepts_handler_test(tmp_path: Path):
    _realtime_project(tmp_path)
    _write(
        tmp_path,
        "tests/Unit/SocketMessageHandlerTest.php",
        "<?php use Realtime\\Services\\SocketMessageHandler; class SocketMessageHandlerTest {}",
    )

    findings = WebSocketHandlerIntegrationTestsMissingRule().analyze(_facts(tmp_path))

    assert findings == []


def test_websocket_handler_integration_tests_missing_sees_ignored_tests_directory(tmp_path: Path):
    _realtime_project(tmp_path)
    _write(
        tmp_path,
        "tests/Unit/Realtime/SocketMessageHandlerTest.php",
        "<?php use Realtime\\Services\\SocketMessageHandler; class SocketMessageHandlerTest {}",
    )
    facts = _facts(tmp_path)
    facts.files = [path for path in facts.files if not path.startswith("tests/")]

    findings = WebSocketHandlerIntegrationTestsMissingRule().analyze(facts)

    assert findings == []


def test_websocket_handler_integration_tests_missing_skips_projects_without_handler(tmp_path: Path):
    _write(tmp_path, "composer.json", REALTIME_COMPOSER)

    findings = WebSocketHandlerIntegrationTestsMissingRule().analyze(_facts(tmp_path))

    assert findings == []


def test_realtime_config_outside_laravel_config_flags_standalone_config(tmp_path: Path):
    _realtime_project(tmp_path)
    _write(tmp_path, "websocket/game_config.php", "<?php return ['max_players' => 4];")

    findings = RealtimeConfigOutsideLaravelConfigRule().analyze(_facts(tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "realtime-config-outside-laravel-config"
    assert findings[0].classification is FindingClassification.ADVISORY
    assert findings[0].severity is Severity.LOW


def test_realtime_config_outside_laravel_config_accepts_laravel_config_bridge(tmp_path: Path):
    _realtime_project(tmp_path)
    _write(tmp_path, "websocket/game_config.php", "<?php return ['max_players' => 4];")
    _write(tmp_path, "config/services.php", "<?php return ['websocket' => ['port' => env('WS_PORT', 8080)]];")
    _write(tmp_path, "app/Support/GameConfig.php", "<?php namespace App\\Support; final class GameConfig {}")

    findings = RealtimeConfigOutsideLaravelConfigRule().analyze(_facts(tmp_path))

    assert findings == []


def test_realtime_config_outside_laravel_config_skips_without_standalone_config(tmp_path: Path):
    _realtime_project(tmp_path)
    _write(tmp_path, "config/services.php", "<?php return ['websocket' => ['port' => 8080]];")

    findings = RealtimeConfigOutsideLaravelConfigRule().analyze(_facts(tmp_path))

    assert findings == []


def test_public_anonymous_mutation_abuse_readiness_flags_missing_controls(tmp_path: Path):
    route = RouteInfo(method="POST", uri="rooms", file_path="routes/web.php", line_number=10, middleware=[])

    findings = PublicAnonymousMutationAbuseReadinessRule().analyze(_facts(tmp_path, [route]))

    assert len(findings) == 1
    assert findings[0].classification is FindingClassification.ADVISORY
    assert findings[0].severity is Severity.MEDIUM
    assert "baseline_controls_incomplete=true" in findings[0].evidence_signals


def test_public_anonymous_mutation_abuse_readiness_keeps_generic_csrf_and_throttle_low_advisory(tmp_path: Path):
    _write(tmp_path, "app/Http/Kernel.php", "<?php use App\\Http\\Middleware\\VerifyCsrfToken;")
    route = RouteInfo(
        method="POST",
        uri="rooms",
        file_path="routes/web.php",
        line_number=10,
        middleware=["throttle:rooms"],
    )

    findings = PublicAnonymousMutationAbuseReadinessRule().analyze(_facts(tmp_path, [route]))

    assert len(findings) == 1
    assert findings[0].classification is FindingClassification.ADVISORY
    assert findings[0].severity is Severity.LOW
    assert "baseline_controls_present=true" in findings[0].evidence_signals


def test_public_anonymous_mutation_abuse_readiness_suppresses_named_limiter_with_csrf(tmp_path: Path):
    _write(tmp_path, "app/Http/Kernel.php", "<?php use App\\Http\\Middleware\\VerifyCsrfToken;")
    _write(
        tmp_path,
        "app/Providers/RouteServiceProvider.php",
        """<?php
use Illuminate\\Support\\Facades\\RateLimiter;
use Illuminate\\Cache\\RateLimiting\\Limit;
RateLimiter::for('rooms.create', fn ($request) => Limit::perMinute(5)->by($request->ip()));
""",
    )
    route = RouteInfo(
        method="POST",
        uri="rooms",
        file_path="routes/web.php",
        line_number=10,
        middleware=["throttle:rooms.create"],
    )

    findings = PublicAnonymousMutationAbuseReadinessRule().analyze(_facts(tmp_path, [route]))

    assert findings == []


def test_public_anonymous_mutation_abuse_readiness_skips_authenticated_mutation(tmp_path: Path):
    route = RouteInfo(
        method="POST",
        uri="rooms",
        file_path="routes/web.php",
        line_number=10,
        middleware=["auth"],
    )

    findings = PublicAnonymousMutationAbuseReadinessRule().analyze(_facts(tmp_path, [route]))

    assert findings == []


def test_realtime_advisory_profile_placement():
    backend_root = Path(__file__).resolve().parents[1]
    startup = Ruleset.load(backend_root / "rulesets" / "startup.yaml")
    balanced = Ruleset.load(backend_root / "rulesets" / "balanced.yaml")
    strict = Ruleset.load(backend_root / "rulesets" / "strict.yaml")
    rule_ids = [
        "realtime-inmemory-state-scalability",
        "websocket-handler-integration-tests-missing",
        "realtime-config-outside-laravel-config",
        "public-anonymous-mutation-abuse-readiness",
    ]

    for rule_id in rule_ids:
        assert startup.get_rule_config(rule_id).enabled is False
        assert balanced.get_rule_config(rule_id).enabled is True
        assert strict.get_rule_config(rule_id).enabled is True
        assert balanced.get_rule_config(rule_id).severity in {"low", "medium"}
