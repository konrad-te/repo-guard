from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
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

        executable = shutil.which(command[0])
        if executable is None:
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
            "GIT_SSL_BACKEND": os.environ.get("GIT_SSL_BACKEND", "openssl" if os.name == "nt" else ""),
            "GIT_CONFIG_COUNT": os.environ.get("GIT_CONFIG_COUNT", "1" if os.name == "nt" else ""),
            "GIT_CONFIG_KEY_0": os.environ.get("GIT_CONFIG_KEY_0", "http.sslBackend" if os.name == "nt" else ""),
            "GIT_CONFIG_VALUE_0": os.environ.get("GIT_CONFIG_VALUE_0", "openssl" if os.name == "nt" else ""),
            "SSL_CERT_FILE": os.environ.get("SSL_CERT_FILE", ""),
            "CURL_CA_BUNDLE": os.environ.get("CURL_CA_BUNDLE", ""),
            "PYTHONUTF8": "1",
        }
        env = {key: value for key, value in env.items() if value}

        try:
            return await asyncio.to_thread(self._run_subprocess, executable, command, cwd, env, start)
        except OSError as exc:
            return CommandResult(
                command=command,
                cwd=str(cwd),
                exit_code=126,
                stderr=str(exc),
                duration_seconds=time.perf_counter() - start,
            )

    def _run_subprocess(
        self,
        executable: str,
        command: list[str],
        cwd: Path,
        env: dict[str, str],
        start: float,
    ) -> CommandResult:
        try:
            completed = subprocess.run(
                [executable, *command[1:]],
                cwd=str(cwd),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout_seconds,
                check=False,
            )
            stdout_bytes = completed.stdout or b""
            stderr_bytes = completed.stderr or b""
            timed_out = False
            exit_code = completed.returncode
        except subprocess.TimeoutExpired as exc:
            stdout_bytes = self._as_bytes(exc.stdout)
            stderr_bytes = self._as_bytes(exc.stderr)
            timed_out = True
            exit_code = 124

        output_truncated = (
            len(stdout_bytes) > self.max_output_bytes
            or len(stderr_bytes) > self.max_output_bytes
        )
        stdout_bytes = stdout_bytes[: self.max_output_bytes]
        stderr_bytes = stderr_bytes[: self.max_output_bytes]
        return CommandResult(
            command=command,
            cwd=str(cwd),
            exit_code=exit_code,
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
            duration_seconds=time.perf_counter() - start,
            timed_out=timed_out,
            output_truncated=output_truncated,
        )

    def _as_bytes(self, value: bytes | str | None) -> bytes:
        if value is None:
            return b""
        if isinstance(value, bytes):
            return value
        return value.encode("utf-8", errors="replace")
