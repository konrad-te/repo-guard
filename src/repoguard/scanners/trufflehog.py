from __future__ import annotations

import json
from pathlib import Path

from repoguard.execution.runner import GuardedCommandRunner
from repoguard.models import AgentStatus, Finding, ScannerResult, Severity
from repoguard.scanners.base import ScannerAgent, run_command_scanner
from repoguard.scanners.paths import is_excluded_path


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
            seen: set[tuple[str, str, int | None]] = set()
            skipped = 0
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
                file_path = file_data.get("file")
                line_number = file_data.get("line")
                if is_excluded_path(file_path, repo_path):
                    skipped += 1
                    continue
                key = (str(detector), str(file_path), line_number)
                if key in seen:
                    skipped += 1
                    continue
                seen.add(key)
                result.findings.append(
                    Finding(
                        scanner=self.name,
                        title=f"{detector} secret detected",
                        severity=Severity.CRITICAL if verified else Severity.HIGH,
                        file=file_path,
                        line=line_number,
                        description="A potential secret was detected. Secret material is redacted from reports.",
                        recommendation="Revoke the credential, rotate it, and remove it from Git history before running or sharing the repo.",
                        evidence="[REDACTED]",
                        rule_id=detector,
                        confidence="verified" if verified else "unverified",
                    )
                )
            result.summary = f"TruffleHog reported {len(result.findings)} potential secret(s)."
            if skipped:
                result.summary += f" Skipped {skipped} duplicate or vendor-folder match(es)."
            if result.status == AgentStatus.FAILED and result.findings:
                result.status = AgentStatus.COMPLETE
        return result
