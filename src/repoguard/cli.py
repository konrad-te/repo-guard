from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from repoguard.config import RepoGuardConfig
from repoguard.models import SEVERITY_ORDER, Severity
from repoguard.orchestrator.runner import ScanOrchestrator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repoguard",
        description="Agentic security analysis for GitHub repositories before running third-party code.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Clone or inspect a repo and generate a security report.")
    scan.add_argument("repo", nargs="?", help="GitHub URL or local repository path.")
    scan.add_argument("--output", type=Path, help="Report directory. Overrides REPORT_DIR.")
    scan.add_argument("--max-tokens", type=int, help="Soft context token budget.")
    scan.add_argument("--hard-token-cap", type=int, help="Hard context token cap.")
    scan.add_argument("--budget-usd", type=float, help="Estimated AI budget warning threshold.")
    scan.add_argument("--concurrency", type=int, help="Maximum scanner agents running in parallel.")
    scan.add_argument("--timeout", type=int, help="Per-scanner timeout in seconds.")
    scan.add_argument("--fail-on", choices=[item.value for item in Severity], help="Exit 1 at or above this severity.")
    scan.add_argument("--no-ai", action="store_true", help="Disable OpenAI enrichment and use deterministic local triage.")
    scan.add_argument("--keep-workspace", action="store_true", help="Keep cloned workspace for debugging.")
    return parser


async def run_scan(args: argparse.Namespace) -> int:
    config = RepoGuardConfig.from_env()
    if args.output:
        config.report_dir = args.output
    if args.max_tokens:
        config.max_context_tokens = args.max_tokens
    if args.hard_token_cap:
        config.hard_token_cap = args.hard_token_cap
    if args.budget_usd is not None:
        config.budget_usd = args.budget_usd
    if args.concurrency:
        config.max_concurrency = args.concurrency
    if args.timeout:
        config.scanner_timeout_seconds = args.timeout
    if args.fail_on:
        config.fail_on_severity = args.fail_on
    if args.no_ai:
        config.ai_enabled = False

    repo = args.repo
    if not repo:
        import os

        repo = os.environ.get("REPO_URL")
    if not repo:
        raise SystemExit("Repo URL/path required, or set REPO_URL in .env.")

    print(f"RepoGuard scanning: {repo}")
    orchestrator = ScanOrchestrator(config)
    report, markdown_path, json_path = await orchestrator.scan(repo, keep_workspace=args.keep_workspace)

    print(f"Report: {markdown_path}")
    print(f"JSON:   {json_path}")
    print(f"Risk:   {report.risk_level.value.upper()}")
    if report.budget:
        for warning in report.budget.warnings:
            print(f"Budget warning: {warning}")

    threshold = Severity(config.fail_on_severity)
    if SEVERITY_ORDER[report.risk_level] >= SEVERITY_ORDER[threshold]:
        return 1
    return 0


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            raise SystemExit(asyncio.run(run_scan(args)))
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        print(f"RepoGuard fatal error: {exc}", file=sys.stderr)
        raise SystemExit(2)
