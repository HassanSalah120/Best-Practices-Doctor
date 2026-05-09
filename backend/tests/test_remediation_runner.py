from __future__ import annotations

import json
import sys

import pytest

from core.remediation.runner import run_verification
from core.verification_helper import infer_verification_commands


def test_infer_verification_commands_detects_phpunit(tmp_path):
    (tmp_path / "phpunit.xml").write_text("<phpunit/>", encoding="utf-8")
    assert "php artisan test" in infer_verification_commands(tmp_path)


def test_infer_verification_commands_does_not_infer_pest_from_allow_plugins_only(tmp_path):
    (tmp_path / "artisan").write_text("#!/usr/bin/env php\n", encoding="utf-8")
    (tmp_path / "phpunit.xml").write_text("<phpunit/>", encoding="utf-8")
    (tmp_path / "composer.json").write_text(
        json.dumps({"config": {"allow-plugins": {"pestphp/pest-plugin": True}}}),
        encoding="utf-8",
    )

    commands = infer_verification_commands(tmp_path)
    assert "php artisan test" in commands
    assert "php artisan test --pest" not in commands


def test_infer_verification_commands_detects_installed_pest_package(tmp_path):
    (tmp_path / "artisan").write_text("#!/usr/bin/env php\n", encoding="utf-8")
    (tmp_path / "composer.json").write_text(
        json.dumps({"require-dev": {"pestphp/pest": "^2.0"}}),
        encoding="utf-8",
    )

    assert "php artisan test --pest" in infer_verification_commands(tmp_path)


def test_infer_verification_commands_detects_package_test(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"test": "vitest", "lint": "eslint ."}}), encoding="utf-8")
    commands = infer_verification_commands(tmp_path)
    assert "npm run test" in commands
    assert "npm run lint" in commands


@pytest.mark.asyncio
async def test_run_verification_records_output_and_exit(tmp_path):
    command = f"{sys.executable} -c \"print('ok')\""
    result = (await run_verification([command], tmp_path))[0]
    assert result.exit_code == 0
    assert "ok" in result.stdout_truncated
    assert not result.timed_out


@pytest.mark.asyncio
async def test_run_verification_times_out(tmp_path):
    command = f"{sys.executable} -c \"import time; time.sleep(2)\""
    result = (await run_verification([command], tmp_path, timeout_seconds=1))[0]
    assert result.timed_out is True


@pytest.mark.asyncio
async def test_run_verification_marks_missing_command(tmp_path):
    result = (await run_verification(["definitely_missing_bpdoctor_command_zz"], tmp_path))[0]
    assert result.command_not_found is True or result.exit_code not in {0, None}
