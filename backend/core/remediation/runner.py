"""Verification runner for remediation runs."""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from pathlib import Path

from core.verification_helper import infer_verification_commands

from .models import VerificationResult


MAX_OUTPUT_CHARS = 2000


async def run_verification(
    commands: list[str],
    cwd: Path,
    timeout_seconds: int = 120,
) -> list[VerificationResult]:
    results: list[VerificationResult] = []
    for command in commands:
        started = datetime.now(timezone.utc)
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                cwd=str(cwd),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
                completed = datetime.now(timezone.utc)
                out = stdout.decode("utf-8", errors="replace")
                err = stderr.decode("utf-8", errors="replace")
                results.append(
                    VerificationResult(
                        command=command,
                        cwd=str(cwd),
                        started_at=started,
                        completed_at=completed,
                        exit_code=proc.returncode,
                        stdout_truncated=_truncate(out),
                        stderr_truncated=_truncate(err),
                        timed_out=False,
                        command_not_found=_looks_command_not_found(proc.returncode, err),
                    )
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                results.append(
                    VerificationResult(
                        command=command,
                        cwd=str(cwd),
                        started_at=started,
                        completed_at=datetime.now(timezone.utc),
                        exit_code=None,
                        stdout_truncated="",
                        stderr_truncated="Timed out",
                        timed_out=True,
                        command_not_found=False,
                    )
                )
        except FileNotFoundError:
            results.append(
                VerificationResult(
                    command=command,
                    cwd=str(cwd),
                    started_at=started,
                    completed_at=datetime.now(timezone.utc),
                    exit_code=None,
                    stdout_truncated="",
                    stderr_truncated="Command not found",
                    timed_out=False,
                    command_not_found=True,
                )
            )
    return results


def _truncate(text: str) -> str:
    value = str(text or "")
    if len(value) <= MAX_OUTPUT_CHARS:
        return value
    return value[:MAX_OUTPUT_CHARS]


def _looks_command_not_found(exit_code: int | None, stderr: str) -> bool:
    if exit_code in {127, 9009}:
        return True
    low = str(stderr or "").lower()
    markers = ["not recognized", "command not found", "is not recognized", "not found"]
    return os.name == "nt" and any(marker in low for marker in markers)


__all__ = ["infer_verification_commands", "run_verification"]
