from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class PatchResult:
    file: Path
    changed: bool
    message: str
    preview: str = ""


def _resolve_inside(root: Path, relative_file: str) -> Path:
    root = root.resolve()
    target = (root / relative_file).resolve()
    if target != root and root not in target.parents:
        raise PermissionError(f"Patch target escapes repository: {relative_file}")
    return target


def apply_exact_replacement(
    repo_root: Path,
    relative_file: str,
    old_text: str,
    new_text: str,
    write: bool = False,
) -> PatchResult:
    if not old_text:
        raise ValueError("old_text must not be empty.")
    target = _resolve_inside(repo_root, relative_file)
    if not target.exists():
        raise FileNotFoundError(f"Patch target not found: {relative_file}")
    if not target.is_file():
        raise IsADirectoryError(f"Patch target is not a file: {relative_file}")

    content = target.read_text(encoding="utf-8")
    count = content.count(old_text)
    if count == 0:
        return PatchResult(target, False, "Exact text was not found.")
    if count > 1:
        return PatchResult(target, False, "Exact text appears multiple times; refusing ambiguous edit.")

    updated = content.replace(old_text, new_text, 1)
    preview = _build_preview(content, updated)
    if write:
        target.write_text(updated, encoding="utf-8")
        return PatchResult(target, True, "Patch applied.", preview)
    return PatchResult(target, False, "Dry run only. Re-run with --yes to apply.", preview)


def _build_preview(before: str, after: str, context_lines: int = 3) -> str:
    before_lines = before.splitlines()
    after_lines = after.splitlines()
    first_changed = 0
    max_len = max(len(before_lines), len(after_lines))
    for index in range(max_len):
        left = before_lines[index] if index < len(before_lines) else None
        right = after_lines[index] if index < len(after_lines) else None
        if left != right:
            first_changed = index
            break
    start = max(0, first_changed - context_lines)
    end = min(max_len, first_changed + context_lines + 4)
    preview_lines = ["[partial edit preview]"]
    for index in range(start, end):
        left = before_lines[index] if index < len(before_lines) else None
        right = after_lines[index] if index < len(after_lines) else None
        line_no = index + 1
        if left == right and left is not None:
            preview_lines.append(f" {line_no}: {left}")
        else:
            if left is not None:
                preview_lines.append(f"-{line_no}: {left}")
            if right is not None:
                preview_lines.append(f"+{line_no}: {right}")
    return "\n".join(preview_lines)
