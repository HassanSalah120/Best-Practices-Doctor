from __future__ import annotations

from pathlib import Path

from schemas.facts import Facts
from rules.devops import (
    AppDebugNotFalseInProductionRule,
    AppEnvNotSetToProductionRule,
    EnvCommittedToGitRule,
    EnvExampleMissingOrOutOfSyncRule,
    MissingQueueWorkerSupervisionRule,
    NoLoggingStrategyConfiguredRule,
    StoragePathsNotInGitignoreRule,
)


def _facts(root: Path) -> Facts:
    composer = root / "composer.json"
    if not composer.exists():
        composer.parent.mkdir(parents=True, exist_ok=True)
        composer.write_text('{"require":{"laravel/framework":"^10.0"}}', encoding="utf-8")
    files = [path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()]
    return Facts(project_path=str(root), files=files)


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_env_example_missing_or_out_of_sync_cases(tmp_path: Path) -> None:
    rule = EnvExampleMissingOrOutOfSyncRule()
    missing = tmp_path / "missing"
    missing.mkdir()
    assert len(rule.analyze(_facts(missing))) == 1

    out_of_sync = tmp_path / "out_of_sync"
    out_of_sync.mkdir()
    _write(out_of_sync, ".env.example", "APP_KEY=\n")
    _write(out_of_sync, ".env", "APP_KEY=base64:x\nPAYMENT_SECRET=secret\n")
    findings = rule.analyze(_facts(out_of_sync))
    assert len(findings) == 1
    assert findings[0].metadata["missing_keys"] == ["PAYMENT_SECRET"]

    synced = tmp_path / "synced"
    synced.mkdir()
    _write(synced, ".env.example", "APP_KEY=\nPAYMENT_SECRET=\n")
    _write(synced, ".env", "APP_KEY=base64:x\nPAYMENT_SECRET=secret\n")
    assert rule.analyze(_facts(synced)) == []

    fresh = tmp_path / "fresh"
    fresh.mkdir()
    _write(fresh, ".env.example", "APP_KEY=\n")
    assert rule.analyze(_facts(fresh)) == []


def test_env_committed_to_git_cases(tmp_path: Path) -> None:
    rule = EnvCommittedToGitRule()
    absent = tmp_path / "absent"
    absent.mkdir()
    assert len(rule.analyze(_facts(absent))) == 1

    missing_env = tmp_path / "missing_env"
    missing_env.mkdir()
    _write(missing_env, ".gitignore", "/storage\n.env.example\n")
    assert len(rule.analyze(_facts(missing_env))) == 1

    safe = tmp_path / "safe"
    safe.mkdir()
    _write(safe, ".gitignore", "/.env\n.env.example\n")
    assert rule.analyze(_facts(safe)) == []


def test_app_debug_not_false_in_production_cases(tmp_path: Path) -> None:
    rule = AppDebugNotFalseInProductionRule()
    literal = tmp_path / "literal"
    _write(literal, "config/app.php", "<?php return ['debug' => true];")
    _write(literal, ".env.example", "APP_DEBUG=false\n")
    assert len(rule.analyze(_facts(literal))) == 1

    env_default = tmp_path / "env_default"
    _write(env_default, "config/app.php", "<?php return ['debug' => env('APP_DEBUG', false)];")
    _write(env_default, ".env.example", "APP_DEBUG=true\n")
    assert len(rule.analyze(_facts(env_default))) == 1

    safe = tmp_path / "safe_debug"
    _write(safe, "config/app.php", "<?php return ['debug' => env('APP_DEBUG', false)];")
    _write(safe, ".env.example", "APP_DEBUG=false\n")
    assert rule.analyze(_facts(safe)) == []


def test_app_env_not_set_to_production_cases(tmp_path: Path) -> None:
    rule = AppEnvNotSetToProductionRule()
    local_env = tmp_path / "local_env"
    _write(local_env, ".env.example", "APP_ENV=local\n")
    assert len(rule.analyze(_facts(local_env))) == 1

    local_config = tmp_path / "local_config"
    _write(local_config, ".env.example", "APP_ENV=production\n")
    _write(local_config, "config/app.php", "<?php return ['env' => 'local'];")
    assert len(rule.analyze(_facts(local_config))) == 1

    safe = tmp_path / "safe_env"
    _write(safe, ".env.example", "APP_ENV=production\n")
    _write(safe, "config/app.php", "<?php return ['env' => env('APP_ENV', 'production')];")
    assert rule.analyze(_facts(safe)) == []


def test_missing_queue_worker_supervision_cases(tmp_path: Path) -> None:
    rule = MissingQueueWorkerSupervisionRule()
    missing = tmp_path / "queue_missing"
    _write(missing, "app/Jobs/SendEmail.php", "<?php class SendEmail implements ShouldQueue {}")
    assert len(rule.analyze(_facts(missing))) == 1

    horizon = tmp_path / "queue_horizon"
    _write(horizon, "app/Jobs/SendEmail.php", "<?php class SendEmail implements ShouldQueue {}")
    _write(horizon, "composer.json", '{"require":{"laravel/horizon":"^5.0"}}')
    assert rule.analyze(_facts(horizon)) == []

    supervisor = tmp_path / "queue_supervisor"
    _write(supervisor, "app/Jobs/SendEmail.php", "<?php class SendEmail implements ShouldQueue {}")
    _write(supervisor, "deploy/worker.conf", "[program:queue]\ncommand=php artisan queue:work\n")
    assert rule.analyze(_facts(supervisor)) == []

    no_queue = tmp_path / "no_queue"
    no_queue.mkdir()
    assert rule.analyze(_facts(no_queue)) == []


def test_no_logging_strategy_configured_cases(tmp_path: Path) -> None:
    rule = NoLoggingStrategyConfiguredRule()
    local_only = tmp_path / "local_only"
    _write(
        local_only,
        "config/logging.php",
        "<?php return ['default' => 'stack', 'channels' => ['stack' => ['channels' => ['single', 'daily']]]];",
    )
    _write(local_only, ".env.example", "LOG_CHANNEL=stack\n")
    assert len(rule.analyze(_facts(local_only))) == 1

    external_env = tmp_path / "external_env"
    _write(external_env, "config/logging.php", "<?php return ['default' => 'stack'];")
    _write(external_env, ".env.example", "LOG_CHANNEL=papertrail\n")
    assert rule.analyze(_facts(external_env)) == []

    external_config = tmp_path / "external_config"
    _write(
        external_config,
        "config/logging.php",
        "<?php return ['default' => 'stack', 'channels' => ['stack' => ['channels' => ['single', 'slack']], 'slack' => []]];",
    )
    _write(external_config, ".env.example", "LOG_CHANNEL=stack\n")
    assert rule.analyze(_facts(external_config)) == []


def test_storage_paths_not_in_gitignore_cases(tmp_path: Path) -> None:
    rule = StoragePathsNotInGitignoreRule()
    missing = tmp_path / "storage_missing"
    _write(missing, ".gitignore", "/storage/*.key\n")
    findings = rule.analyze(_facts(missing))
    assert len(findings) == 1
    assert "/bootstrap/cache/" in findings[0].metadata["missing_paths"]

    absent = tmp_path / "storage_absent"
    absent.mkdir()
    assert len(rule.analyze(_facts(absent))) == 1

    safe = tmp_path / "storage_safe"
    _write(safe, ".gitignore", "/storage/*.key\n/bootstrap/cache/\n/public/storage\n/storage/app/public\n")
    assert rule.analyze(_facts(safe)) == []
