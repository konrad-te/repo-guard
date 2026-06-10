from __future__ import annotations

import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from repoguard.execution.runner import GuardedCommandRunner


GIT_URL_RE = re.compile(r"^(https://github\.com/|git@github\.com:)[A-Za-z0-9_.\-/]+(?:\.git)?$")


@dataclass(slots=True)
class Workspace:
    root: Path
    repo_path: Path
    cleanup_required: bool = True

    def cleanup(self) -> None:
        if self.cleanup_required and self.root.exists():
            shutil.rmtree(self.root, ignore_errors=True)


def repo_slug(repo: str) -> str:
    local = Path(repo).expanduser()
    if local.exists():
        name = local.resolve().name or "local-repo"
        return re.sub(r"[^A-Za-z0-9_.-]+", "-", name)[:80]
    parsed = urlparse(repo)
    value = parsed.path if parsed.path else repo
    value = value.rstrip("/").replace(".git", "")
    name = value.split("/")[-1] or "repo"
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", name)[:80]


async def prepare_workspace(repo: str, timeout_seconds: int, max_output_bytes: int) -> Workspace:
    local = Path(repo).expanduser()
    if local.exists() and local.is_dir():
        resolved = local.resolve()
        return Workspace(root=resolved, repo_path=resolved, cleanup_required=False)

    if not GIT_URL_RE.match(repo):
        raise ValueError(
            "Repo must be an existing local directory or a GitHub URL like "
            "https://github.com/org/repo"
        )

    root = Path(tempfile.mkdtemp(prefix="repoguard-")).resolve()
    repo_path = root / repo_slug(repo)
    runner = GuardedCommandRunner(root, timeout_seconds=timeout_seconds, max_output_bytes=max_output_bytes)
    result = await runner.run(["git", "clone", "--depth", "1", repo, str(repo_path)], cwd=root)
    if result.exit_code != 0:
        shutil.rmtree(root, ignore_errors=True)
        raise RuntimeError(f"git clone failed: {result.stderr or result.stdout}")
    return Workspace(root=root, repo_path=repo_path, cleanup_required=True)
