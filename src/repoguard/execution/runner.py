from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

from repoguard.execution.policy import ExecutionPolicy
from repoguard.models import CommandResult


class GuardedCommandRunner:
    def __init__(
        self,
        workspace_root: Path,
        policy: ExecutionPolicy | None = None,
        timeout_seconds: int = 300,
        max_output_bytes: int = 1_048_576,
    ) -> None:
        self.workspace_root = workspace_root
        self.policy = policy or ExecutionPolicy()
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    async def run(self, command: list[str], cwd: Path | None = None) -> CommandResult:
        cwd = cwd or self.workspace_root
        start = time.perf_counter()
        try:
            self.policy.validate(command, cwd, self.workspace_root)
        except PermissionError as exc:
            return CommandResult(
                command=command,
                cwd=str(cwd),
                exit_code=None,
                blocked_reason=str(exc),
                duration_seconds=time.perf_counter() - start,
            )

        if not self.policy.binary_exists(command[0]):
            return CommandResult(
                command=command,
                cwd=str(cwd),
                exit_code=127,
                stderr=f"Required scanner binary not found: {command[0]}",
                duration_seconds=time.perf_counter() - start,
            )

        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            "USERPROFILE": os.environ.get("USERPROFILE", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "TMP": os.environ.get("TMP", ""),
            "TEMP": os.environ.get("TEMP", ""),
            "PYTHONUTF8": "1",
        }
        env = {key: value for key, value in env.items() if value}

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                cwd=str(cwd),
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(), timeout=self.timeout_seconds
                )
                timed_out = False
            except asyncio.TimeoutError:
                process.kill()
                stdout_bytes, stderr_bytes = await process.communicate()
                timed_out = True

            output_truncated = (
                len(stdout_bytes) > self.max_output_bytes
                or len(stderr_bytes) > self.max_output_bytes
            )
            stdout_bytes = stdout_bytes[: self.max_output_bytes]
            stderr_bytes = stderr_bytes[: self.max_output_bytes]
            return CommandResult(
                command=command,
                cwd=str(cwd),
                exit_code=process.returncode,
                stdout=stdout_bytes.decode("utf-8", errors="replace"),
                stderr=stderr_bytes.decode("utf-8", errors="replace"),
                duration_seconds=time.perf_counter() - start,
                timed_out=timed_out,
                output_truncated=output_truncated,
            )
        except OSError as exc:
            return CommandResult(
                command=command,
                cwd=str(cwd),
                exit_code=126,
                stderr=str(exc),
                duration_seconds=time.perf_counter() - start,
            )
