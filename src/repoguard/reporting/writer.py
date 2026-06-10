from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

from repoguard.models import ScanReport, SEVERITY_ORDER
from repoguard.orchestrator.context import redact_secrets


class PartialReportWriter:
    def __init__(self, report_dir: Path, slug: str) -> None:
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        self.output_dir = report_dir / slug / timestamp
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.markdown_path = self.output_dir / "report.md"
        self.json_path = self.output_dir / "findings.json"

    def write(self, report: ScanReport) -> None:
        self._atomic_write(self.json_path, json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
        self._atomic_write(self.markdown_path, self._markdown(report))

    def _atomic_write(self, path: Path, text: str) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(redact_secrets(text), encoding="utf-8")
        os.replace(tmp, path)

    def _markdown(self, report: ScanReport) -> str:
        report.recalculate_risk()
        lines = [
            "# RepoGuard Security Report",
            "",
            f"- Repository: `{report.repo}`",
            f"- Local path: `{report.repo_path}`",
            f"- Status: `{report.status}`",
            f"- Risk level: `{report.risk_level.value.upper()}`",
            f"- Started: `{report.started_at}`",
            f"- Finished: `{report.finished_at or 'running'}`",
            "",
            "## Executive Summary",
            "",
            report.summary or "Scan is running. Partial results are shown below.",
            "",
            "## Budget",
            "",
        ]
        if report.budget:
            lines.extend(
                [
                    f"- Estimated tokens used: `{report.budget.used_tokens}` / `{report.budget.hard_token_cap}`",
                    f"- Estimated cost: `${report.budget.estimated_cost_usd:.6f}`",
                    f"- Hard cap reached: `{report.budget.capped}`",
                ]
            )
            for warning in report.budget.warnings:
                lines.append(f"- Warning: {warning}")
        else:
            lines.append("- Budget snapshot unavailable.")

        lines.extend(["", "## Scanner Agents", ""])
        for result in report.scanner_results:
            lines.extend(
                [
                    f"### {result.name}",
                    "",
                    f"- Status: `{result.status.value}`",
                    f"- Duration: `{result.duration_seconds:.2f}s`",
                    f"- Findings: `{len(result.findings)}`",
                ]
            )
            if result.error:
                lines.append(f"- Error: `{result.error[:500]}`")
            if result.summary:
                lines.extend(["", result.summary])
            lines.append("")

        findings = sorted(
            report.all_findings(),
            key=lambda finding: SEVERITY_ORDER[finding.severity],
            reverse=True,
        )
        lines.extend(["## Findings", ""])
        if not findings:
            lines.append("No findings were normalized by RepoGuard.")
        for index, finding in enumerate(findings, start=1):
            location = finding.file or "unknown"
            if finding.line:
                location += f":{finding.line}"
            lines.extend(
                [
                    f"### {index}. {finding.title}",
                    "",
                    f"- Severity: `{finding.severity.value}`",
                    f"- Scanner: `{finding.scanner}`",
                    f"- Location: `{location}`",
                    f"- Rule: `{finding.rule_id or 'n/a'}`",
                    "",
                    finding.description or "No scanner description provided.",
                    "",
                    f"Recommendation: {finding.recommendation or 'Review before running this repository.'}",
                    "",
                ]
            )

        lines.extend(["## Recommendations", ""])
        if report.recommendations:
            lines.extend(f"- {item}" for item in report.recommendations)
        else:
            lines.append("- Awaiting final agent recommendations.")
        lines.append("")
        return "\n".join(lines)
