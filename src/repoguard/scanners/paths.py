from __future__ import annotations

from pathlib import Path


EXCLUDED_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "env",
    "node_modules",
    "reports",
    "venv",
}


def is_excluded_path(path: str | Path | None, repo_path: Path | None = None) -> bool:
    if not path:
        return False

    candidate = Path(str(path))
    if repo_path is not None:
        try:
            candidate = candidate.resolve().relative_to(repo_path.resolve())
        except (OSError, ValueError):
            pass

    parts = {part.lower() for part in candidate.parts}
    return bool(parts & EXCLUDED_DIRS)


def bandit_exclude_paths(repo_path: Path) -> str:
    return ",".join(str(repo_path / name) for name in sorted(EXCLUDED_DIRS))


def semgrep_exclude_args() -> list[str]:
    return [item for pattern in sorted(EXCLUDED_DIRS) for item in ("--exclude", pattern)]
