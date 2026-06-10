from __future__ import annotations

import json
from pathlib import Path

from repoguard.execution.runner import GuardedCommandRunner
from repoguard.models import AgentStatus, Finding, ScannerResult, Severity
from repoguard.scanners.base import ScannerAgent, run_command_scanner


class PipAuditScanner(ScannerAgent):
    name = "pip-audit"
    description = "Python dependency vulnerability auditing."

    async def scan(self, repo_path: Path, runner: GuardedCommandRunner) -> ScannerResult:
        requirements = sorted(repo_path.rglob("requirements*.txt"))
        if not requirements:
            return self.unavailable("No requirements*.txt files found; pip-audit skipped.")

        findings: list[Finding] = []
        summaries: list[str] = []
        final_result: ScannerResult | None = None
        for req in requirements[:5]:
            result = await run_command_scanner(
                self,
                repo_path,
                runner,
                ["pip-audit", "-r", str(req), "-f", "json"],
            )
            final_result = result
            if result.command and result.command.stdout:
                try:
                    payload = json.loads(result.command.stdout)
                except json.JSONDecodeError:
                    summaries.append(f"{req}: output was not valid JSON")
                    continue
                for dep in payload.get("dependencies", []):
                    for vuln in dep.get("vulns", []):
                        aliases = ", ".join(vuln.get("aliases", []))
                        fix_versions = ", ".join(vuln.get("fix_versions", [])) or "No fixed version reported"
                        findings.append(
                            Finding(
                                scanner=self.name,
                                title=f"{dep.get('name')} {vuln.get('id')}",
                                severity=Severity.HIGH,
                                file=str(req),
                                description=vuln.get("description", ""),
                                recommendation=f"Upgrade {dep.get('name')} to: {fix_versions}.",
                                evidence=aliases,
                                rule_id=vuln.get("id"),
                            )
                        )
                summaries.append(f"{req}: {len(findings)} cumulative finding(s)")

        if final_result is None:
            return self.unavailable("No auditable requirement files found.")
        final_result.findings = findings
        final_result.summary = "; ".join(summaries) or f"pip-audit reported {len(findings)} finding(s)."
        if findings and final_result.status == AgentStatus.FAILED:
            final_result.status = AgentStatus.COMPLETE
        return final_result
