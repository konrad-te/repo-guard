from __future__ import annotations

import json
from pathlib import Path

from repoguard.execution.runner import GuardedCommandRunner
from repoguard.models import AgentStatus, Finding, ScannerResult, Severity
from repoguard.scanners.base import ScannerAgent, run_command_scanner
from repoguard.scanners.paths import semgrep_exclude_args


def _severity(extra: dict) -> Severity:
    value = str(extra.get("severity", "INFO")).lower()
    if value in {"error", "high"}:
        return Severity.HIGH
    if value in {"warning", "medium"}:
        return Severity.MEDIUM
    if value in {"low"}:
        return Severity.LOW
    return Severity.INFO


class SemgrepScanner(ScannerAgent):
    name = "semgrep"
    description = "Multi-language SAST using Semgrep rules."

    async def scan(self, repo_path: Path, runner: GuardedCommandRunner) -> ScannerResult:
        result = await run_command_scanner(
            self,
            repo_path,
            runner,
            [
                "semgrep",
                "scan",
                "--config",
                "auto",
                "--json",
                *semgrep_exclude_args(),
                str(repo_path),
            ],
        )
        if result.command and result.command.stdout:
            try:
                payload = json.loads(result.command.stdout)
                for item in payload.get("results", []):
                    extra = item.get("extra", {})
                    start = item.get("start", {})
                    result.findings.append(
                        Finding(
                            scanner=self.name,
                            title=extra.get("message") or item.get("check_id") or "Semgrep finding",
                            severity=_severity(extra),
                            file=item.get("path"),
                            line=start.get("line"),
                            description=extra.get("message", ""),
                            recommendation="Review the matching Semgrep rule and validate exploitability before running the repo.",
                            evidence=extra.get("lines", ""),
                            rule_id=item.get("check_id"),
                            confidence=str(extra.get("metadata", {}).get("confidence", "")) or None,
                        )
                    )
                result.summary = f"Semgrep reported {len(result.findings)} code finding(s)."
                if result.status == AgentStatus.FAILED and result.findings:
                    result.status = AgentStatus.COMPLETE
            except json.JSONDecodeError:
                result.summary = "Semgrep output was not valid JSON."
        return result
