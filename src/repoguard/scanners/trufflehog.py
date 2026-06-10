from __future__ import annotations

import json
from pathlib import Path

from repoguard.execution.runner import GuardedCommandRunner
from repoguard.models import AgentStatus, Finding, ScannerResult, Severity
from repoguard.scanners.base import ScannerAgent, run_command_scanner


class TruffleHogScanner(ScannerAgent):
    name = "trufflehog"
    description = "Secret scanning with TruffleHog filesystem mode."

    async def scan(self, repo_path: Path, runner: GuardedCommandRunner) -> ScannerResult:
        result = await run_command_scanner(
            self,
            repo_path,
            runner,
            ["trufflehog", "filesystem", str(repo_path), "--json", "--no-update"],
        )
        if result.command and result.command.stdout:
            for line in result.command.stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                source = item.get("SourceMetadata", {}).get("Data", {})
                file_data = source.get("Filesystem", {})
                detector = item.get("DetectorName", "Secret")
                verified = item.get("Verified", False)
                result.findings.append(
                    Finding(
                        scanner=self.name,
                        title=f"{detector} secret detected",
                        severity=Severity.CRITICAL if verified else Severity.HIGH,
                        file=file_data.get("file"),
                        line=file_data.get("line"),
                        description="A potential secret was detected. Secret material is redacted from reports.",
                        recommendation="Revoke the credential, rotate it, and remove it from Git history before running or sharing the repo.",
                        evidence="[REDACTED]",
                        rule_id=detector,
                        confidence="verified" if verified else "unverified",
                    )
                )
            result.summary = f"TruffleHog reported {len(result.findings)} potential secret(s)."
            if result.status == AgentStatus.FAILED and result.findings:
                result.status = AgentStatus.COMPLETE
        return result
