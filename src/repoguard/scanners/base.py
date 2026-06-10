from __future__ import annotations

import time
from abc import ABC, abstractmethod
from pathlib import Path

from repoguard.execution.runner import GuardedCommandRunner
from repoguard.models import AgentStatus, ScannerResult
from repoguard.orchestrator.context import compress_output


class ScannerAgent(ABC):
    name: str
    description: str

    @abstractmethod
    async def scan(self, repo_path: Path, runner: GuardedCommandRunner) -> ScannerResult:
        raise NotImplementedError

    def unavailable(self, summary: str) -> ScannerResult:
        return ScannerResult(name=self.name, status=AgentStatus.SKIPPED, summary=summary).finish()


async def run_command_scanner(
    scanner: ScannerAgent,
    repo_path: Path,
    runner: GuardedCommandRunner,
    command: list[str],
) -> ScannerResult:
    started = time.perf_counter()
    result = ScannerResult(name=scanner.name, status=AgentStatus.RUNNING)
    command_result = await runner.run(command, cwd=repo_path)
    result.command = command_result
    result.duration_seconds = time.perf_counter() - started
    result.compressed_output = compress_output(
        f"STDOUT:\n{command_result.stdout}\n\nSTDERR:\n{command_result.stderr}"
    )
    if command_result.blocked_reason:
        result.status = AgentStatus.BLOCKED
        result.error = command_result.blocked_reason
    elif command_result.timed_out:
        result.status = AgentStatus.TIMED_OUT
        result.error = "Scanner timed out."
    elif command_result.exit_code == 127:
        result.status = AgentStatus.SKIPPED
        result.error = command_result.stderr
    elif command_result.exit_code not in (0, None):
        result.status = AgentStatus.FAILED
        result.error = command_result.stderr or command_result.stdout or f"Exit code {command_result.exit_code}"
    else:
        result.status = AgentStatus.COMPLETE
    return result.finish()
