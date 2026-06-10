from __future__ import annotations

from collections import Counter
from pathlib import Path

from repoguard.execution.runner import GuardedCommandRunner
from repoguard.models import AgentStatus, Finding, ScannerResult, Severity
from repoguard.scanners.base import ScannerAgent


SUSPICIOUS_FILES = {
    ".env": Severity.HIGH,
    "id_rsa": Severity.CRITICAL,
    "id_dsa": Severity.CRITICAL,
    "credentials": Severity.HIGH,
    "settings.py": Severity.LOW,
}

IGNORED_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "node_modules",
    "dist",
    "build",
    "reports",
}


class FilesystemScanner(ScannerAgent):
    name = "filesystem-agent"
    description = "Repository metadata, language, and risky-file inspection."

    async def scan(self, repo_path: Path, runner: GuardedCommandRunner) -> ScannerResult:
        result = ScannerResult(name=self.name, status=AgentStatus.COMPLETE)
        suffixes: Counter[str] = Counter()
        total_files = 0
        for path in repo_path.rglob("*"):
            if any(part in IGNORED_DIRS for part in path.parts) or not path.is_file():
                continue
            total_files += 1
            if path.suffix:
                suffixes[path.suffix.lower()] += 1
            lower_name = path.name.lower()
            if lower_name in SUSPICIOUS_FILES:
                result.findings.append(
                    Finding(
                        scanner=self.name,
                        title=f"Potentially sensitive file committed: {path.name}",
                        severity=SUSPICIOUS_FILES[lower_name],
                        file=str(path.relative_to(repo_path)),
                        description="The repository contains a file name commonly associated with credentials or local configuration.",
                        recommendation="Inspect the file before running the project. Remove or rotate secrets if present.",
                    )
                )
        common = ", ".join(f"{suffix}:{count}" for suffix, count in suffixes.most_common(8))
        result.summary = f"Scanned {total_files} files. Common extensions: {common or 'none'}."
        return result.finish()
