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
    "venv",
    "env",
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
        tracked_files = await _git_tracked_files(repo_path, runner)
        for path in repo_path.rglob("*"):
            if any(part in IGNORED_DIRS for part in path.parts) or not path.is_file():
                continue
            total_files += 1
            if path.suffix:
                suffixes[path.suffix.lower()] += 1
            lower_name = path.name.lower()
            if lower_name in SUSPICIOUS_FILES:
                relative = path.relative_to(repo_path).as_posix()
                tracked = tracked_files is not None and relative in tracked_files
                severity = SUSPICIOUS_FILES[lower_name] if tracked else Severity.MEDIUM
                title = (
                    f"Potentially sensitive file committed: {path.name}"
                    if tracked
                    else f"Potentially sensitive local file present: {path.name}"
                )
                description = (
                    "Git tracks this file, so it may be committed or pushed with the repository."
                    if tracked
                    else "This sensitive-looking file exists in the local working tree. RepoGuard did not confirm that Git tracks it."
                )
                result.findings.append(
                    Finding(
                        scanner=self.name,
                        title=title,
                        severity=severity,
                        file=str(path.relative_to(repo_path)),
                        description=description,
                        recommendation=(
                            "If this file contains real secrets, keep it out of Git, rotate exposed values, "
                            "and keep only a safe .env.example template in the repository."
                        ),
                    )
                )
        common = ", ".join(f"{suffix}:{count}" for suffix, count in suffixes.most_common(8))
        result.summary = f"Scanned {total_files} files. Common extensions: {common or 'none'}."
        return result.finish()


async def _git_tracked_files(repo_path: Path, runner: GuardedCommandRunner) -> set[str] | None:
    if not (repo_path / ".git").exists():
        return None
    result = await runner.run(["git", "ls-files", "-z"], cwd=repo_path)
    if result.exit_code != 0:
        return None
    return {item for item in result.stdout.split("\0") if item}
