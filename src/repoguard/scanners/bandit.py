from __future__ import annotations

import json
from pathlib import Path

from repoguard.execution.runner import GuardedCommandRunner
from repoguard.models import AgentStatus, Finding, ScannerResult, Severity
from repoguard.scanners.base import ScannerAgent, run_command_scanner
from repoguard.scanners.paths import bandit_exclude_paths


SEVERITY_MAP = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
}

class BanditScanner(ScannerAgent):
    name = "bandit"
    description = "Python static application security testing."

    async def scan(self, repo_path: Path, runner: GuardedCommandRunner) -> ScannerResult:
        result = await run_command_scanner(
            self,
            repo_path,
            runner,
            ["bandit", "-r", str(repo_path), "-f", "json", "-x", bandit_exclude_paths(repo_path)],
        )
        if result.command and result.command.stdout:
            try:
                payload = json.loads(result.command.stdout)
                for item in payload.get("results", []):
                    result.findings.append(
                        Finding(
                            scanner=self.name,
                            title=item.get("test_name") or item.get("issue_text") or "Bandit finding",
                            severity=SEVERITY_MAP.get(item.get("issue_severity", "LOW"), Severity.LOW),
                            file=item.get("filename"),
                            line=item.get("line_number"),
                            description=item.get("issue_text", ""),
                            recommendation="Review the flagged Python code and apply Bandit's remediation guidance.",
                            evidence=item.get("code", ""),
                            rule_id=item.get("test_id"),
                            confidence=item.get("issue_confidence"),
                        )
                    )
                result.summary = f"Bandit reported {len(result.findings)} Python security finding(s)."
                if result.status == AgentStatus.FAILED and result.findings:
                    result.status = AgentStatus.COMPLETE
            except json.JSONDecodeError:
                result.summary = "Bandit output was not valid JSON."
        return result
