import asyncio
import tempfile
import unittest
from pathlib import Path

from repoguard.config import RepoGuardConfig
from repoguard.execution.runner import GuardedCommandRunner
from repoguard.models import AgentStatus, Finding, ScannerResult, Severity
from repoguard.orchestrator.runner import ScanOrchestrator
from repoguard.scanners.base import ScannerAgent


class FakeScanner(ScannerAgent):
    def __init__(self, name: str, delay: float, severity: Severity | None = None):
        self.name = name
        self.description = name
        self.delay = delay
        self.severity = severity

    async def scan(self, repo_path: Path, runner: GuardedCommandRunner) -> ScannerResult:
        await asyncio.sleep(self.delay)
        findings = []
        if self.severity:
            findings.append(Finding(scanner=self.name, title="fake", severity=self.severity))
        return ScannerResult(
            name=self.name,
            status=AgentStatus.COMPLETE,
            findings=findings,
            summary=f"{self.name} done",
        ).finish()


def config(tmp_path: Path) -> RepoGuardConfig:
    return RepoGuardConfig(
        report_dir=tmp_path / "reports",
        scanner_timeout_seconds=5,
        max_output_bytes=10000,
        max_concurrency=5,
        max_context_tokens=10000,
        warn_token_ratio=0.8,
        hard_token_cap=12000,
        budget_usd=10,
        input_cost_per_1k=0.001,
        output_cost_per_1k=0.001,
        openai_api_key=None,
        openai_model="test",
        fail_on_severity="high",
        ai_enabled=False,
    )


class OrchestratorTests(unittest.IsolatedAsyncioTestCase):
    async def test_scanners_run_concurrently(self):
        with tempfile.TemporaryDirectory() as temp:
            tmp_path = Path(temp)
            repo = tmp_path / "repo"
            repo.mkdir()
            orchestrator = ScanOrchestrator(
                config(tmp_path),
                scanners=[
                    FakeScanner("a", 0.2, Severity.LOW),
                    FakeScanner("b", 0.2, Severity.HIGH),
                ],
            )
            start = asyncio.get_event_loop().time()
            report, md, js = await orchestrator.scan(str(repo))
            elapsed = asyncio.get_event_loop().time() - start
            self.assertLess(elapsed, 0.35)
            self.assertEqual(report.risk_level, Severity.HIGH)
            self.assertTrue(md.exists())
            self.assertTrue(js.exists())

    async def test_scanner_failure_is_recorded(self):
        class BrokenScanner(ScannerAgent):
            name = "broken"
            description = "broken"

            async def scan(self, repo_path: Path, runner: GuardedCommandRunner) -> ScannerResult:
                raise RuntimeError("boom")

        with tempfile.TemporaryDirectory() as temp:
            tmp_path = Path(temp)
            repo = tmp_path / "repo"
            repo.mkdir()
            orchestrator = ScanOrchestrator(config(tmp_path), scanners=[BrokenScanner()])
            report, _, _ = await orchestrator.scan(str(repo))
            self.assertEqual(report.scanner_results[0].status, AgentStatus.FAILED)
            self.assertIn("boom", report.scanner_results[0].error or "")


if __name__ == "__main__":
    unittest.main()
