from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path


SHELL_METACHARS = {"&&", "||", ";", "|", ">", "<", "$(", "`", "\n", "\r"}


@dataclass(slots=True)
class ExecutionPolicy:
    allowed_binaries: set[str] = field(
        default_factory=lambda: {
            "git",
            "bandit",
            "semgrep",
            "trufflehog",
            "pip-audit",
            "pip-licenses",
        }
    )
    allowed_git_subcommands: set[str] = field(default_factory=lambda: {"clone"})

    def validate(self, command: list[str], cwd: Path, workspace_root: Path) -> None:
        if not command:
            raise PermissionError("Empty command is not allowed.")
        binary = Path(command[0]).name
        if binary.endswith(".exe"):
            binary = binary[:-4]
        if binary not in self.allowed_binaries:
            raise PermissionError(f"Command '{binary}' is not allowlisted.")
        for arg in command:
            if any(metachar in arg for metachar in SHELL_METACHARS):
                raise PermissionError(f"Shell metacharacter blocked in argument: {arg!r}")
        resolved_cwd = cwd.resolve()
        resolved_root = workspace_root.resolve()
        if resolved_cwd != resolved_root and resolved_root not in resolved_cwd.parents:
            raise PermissionError(f"Working directory escapes workspace: {resolved_cwd}")
        if binary == "git":
            if len(command) < 2 or command[1] not in self.allowed_git_subcommands:
                raise PermissionError("Only 'git clone' is allowed.")
            if "--upload-pack" in command:
                raise PermissionError("git --upload-pack is blocked.")

    def binary_exists(self, command: str) -> bool:
        return shutil.which(command) is not None
