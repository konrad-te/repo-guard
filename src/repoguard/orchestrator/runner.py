from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

from repoguard.ai.report_agent import HeuristicReportAgent, OpenAIReportAgent, ReportAgent
from repoguard.config import RepoGuardConfig
from repoguard.execution.runner import GuardedCommandRunner
from repoguard.models import AgentStatus, ScanReport, ScannerResult
from repoguard.orchestrator.budget import BudgetExceeded, TokenBudget
from repoguard.orchestrator.context import compact_json
from repoguard.reporting.writer import PartialReportWriter
from repoguard.scanners.base import ScannerAgent
from repoguard.scanners.registry import default_scanners
from repoguard.workspace import prepare_workspace, repo_slug


class ScanOrchestrator:
    def __init__(
        self,
        config: RepoGuardConfig,
        scanners: list[ScannerAgent] | None = None,
        report_agent: ReportAgent | None = None,
    ) -> None:
        self.config = config
        self.scanners = scanners or default_scanners()
        if report_agent:
            self.report_agent = report_agent
        elif config.ai_enabled and config.openai_api_key:
            self.report_agent = OpenAIReportAgent(config.openai_api_key, config.openai_model)
        else:
            self.report_agent = HeuristicReportAgent()

    async def scan(self, repo: str, keep_workspace: bool = False) -> tuple[ScanReport, Path, Path]:
        workspace = await prepare_workspace(
            repo,
            timeout_seconds=self.config.scanner_timeout_seconds,
            max_output_bytes=self.config.max_output_bytes,
        )
        if keep_workspace:
            workspace.cleanup_required = False

        started_at = datetime.now(timezone.utc).isoformat()
        report = ScanReport(repo=repo, repo_path=str(workspace.repo_path), started_at=started_at)
        writer = PartialReportWriter(self.config.report_dir, repo_slug(repo))
        budget = TokenBudget(
            max_context_tokens=self.config.max_context_tokens,
            hard_token_cap=self.config.hard_token_cap,
            warn_ratio=self.config.warn_token_ratio,
            budget_usd=self.config.budget_usd,
            input_cost_per_1k=self.config.input_cost_per_1k,
            output_cost_per_1k=self.config.output_cost_per_1k,
        )
        report.budget = budget.snapshot()
        writer.write(report)

        try:
            runner = GuardedCommandRunner(
                workspace.repo_path,
                timeout_seconds=self.config.scanner_timeout_seconds,
                max_output_bytes=self.config.max_output_bytes,
            )
            await self._run_scanners(report, writer, budget, workspace.repo_path, runner)
            await self.report_agent.enrich(report, budget)
            report.status = "complete"
        except BudgetExceeded as exc:
            report.status = "partial-budget-capped"
            report.summary = f"Scan stopped because the hard context budget was reached: {exc}"
        finally:
            report.finished_at = datetime.now(timezone.utc).isoformat()
            report.recalculate_risk()
            report.budget = budget.snapshot()
            writer.write(report)
            workspace.cleanup()

        return report, writer.markdown_path, writer.json_path

    async def _run_scanners(
        self,
        report: ScanReport,
        writer: PartialReportWriter,
        budget: TokenBudget,
        repo_path: Path,
        runner: GuardedCommandRunner,
    ) -> None:
        if not self.scanners:
            report.scanner_results.append(
                ScannerResult(name="orchestrator", status=AgentStatus.SKIPPED, summary="No scanners configured.").finish()
            )
            writer.write(report)
            return

        semaphore = asyncio.Semaphore(max(1, self.config.max_concurrency))

        async def run_one(scanner: ScannerAgent) -> ScannerResult:
            async with semaphore:
                try:
                    return await scanner.scan(repo_path, runner)
                except Exception as exc:
                    return ScannerResult(
                        name=scanner.name,
                        status=AgentStatus.FAILED,
                        error=f"{type(exc).__name__}: {exc}",
                    ).finish()

        tasks = {asyncio.create_task(run_one(scanner)): scanner.name for scanner in self.scanners}
        for task in asyncio.as_completed(tasks):
            result = await task
            try:
                budget.add_context(f"{result.name}-compressed-output", result.compressed_output)
                budget.add_context(f"{result.name}-normalized-findings", compact_json(result.to_dict(), max_chars=8_000))
            except BudgetExceeded:
                report.scanner_results.append(result)
                report.budget = budget.snapshot()
                writer.write(report)
                raise
            report.scanner_results.append(result)
            report.recalculate_risk()
            report.budget = budget.snapshot()
            writer.write(report)
