from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from repoguard.editing.patcher import _build_preview


UPLOAD_GUARD_HELPER = '''
MAX_UPLOAD_FILES = 10
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
ALLOWED_UPLOAD_EXTENSIONS = {".jpg", ".jpeg", ".png", ".pdf", ".txt"}


def _allowed_upload_filename(filename):
    suffix = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return suffix in ALLOWED_UPLOAD_EXTENSIONS
'''

FASTAPI_UPLOAD_GUARD_HELPER = '''
MAX_UPLOAD_FILES = 10
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
ALLOWED_UPLOAD_EXTENSIONS = {".jpg", ".jpeg", ".png", ".pdf", ".txt", ".json"}


def _allowed_upload_filename(filename: str | None) -> bool:
    if not filename or "." not in filename:
        return False
    suffix = "." + filename.rsplit(".", 1)[-1].lower()
    return suffix in ALLOWED_UPLOAD_EXTENSIONS
'''

FASTAPI_TYPE_VALIDATION_HELPER = '''
ALLOWED_UPLOAD_EXTENSIONS = {".json"}


def _allowed_upload_filename(filename: str | None) -> bool:
    if not filename or "." not in filename:
        return False
    suffix = "." + filename.rsplit(".", 1)[-1].lower()
    return suffix in ALLOWED_UPLOAD_EXTENSIONS
'''


@dataclass(slots=True)
class FixResult:
    file: Path
    changed: bool
    fixable: bool
    title: str
    message: str
    preview: str = ""
    steps: tuple[str, ...] = ()


LICENSE_REVIEW_NOTE = """# License Review Needed

RepoGuard did not find a top-level LICENSE file in this repository.

Before copying, redistributing, or using this project commercially:

- confirm the intended license with the maintainer or project owner
- add the chosen license text to a top-level LICENSE file
- document any dependency license obligations

This file is a review note, not a legal license.
"""


def suggest_or_apply_upload_fix(repo_root: Path, relative_file: str, write: bool = False) -> FixResult:
    target = _resolve_inside(repo_root, relative_file)
    if not target.exists():
        raise FileNotFoundError(f"Fix target not found: {relative_file}")
    if not target.is_file():
        raise IsADirectoryError(f"Fix target is not a file: {relative_file}")
    if target.suffix.lower() != ".py":
        return FixResult(
            target,
            changed=False,
            fixable=False,
            title="No safe auto-fix available",
            message="RepoGuard currently has upload auto-fixes for known Python Flask and FastAPI handlers only.",
            steps=("Checked finding type.", "Refused because the target is not a Python source file."),
        )

    original = target.read_text(encoding="utf-8")
    updated = _patch_flask_upload_handler(original)
    if updated == original:
        updated = _patch_fastapi_upload_handler(original)
    if updated == original:
        return FixResult(
            target,
            changed=False,
            fixable=False,
            title="No safe auto-fix available",
            message=(
                "RepoGuard could not match a known unsafe Flask or FastAPI upload pattern in this file. "
                "Use the recommendation as a manual patch guide."
            ),
            steps=(
                "Resolved the file inside the selected repository.",
                "Checked for supported Flask and FastAPI upload patterns.",
                "Refused to edit because no known safe pattern matched.",
            ),
        )

    preview = _build_preview(original, updated, context_lines=5)
    steps = (
        "Resolved the target file inside the selected repository.",
        "Matched a supported Python upload-handler pattern.",
        "Inserted explicit count, size, and file-type guards.",
        "Generated a unified diff preview before writing.",
    )
    if write:
        target.write_text(updated, encoding="utf-8")
        return FixResult(
            target,
            changed=True,
            fixable=True,
            title="Upload guard applied",
            message="Added upload count, size, and extension checks.",
            preview=preview,
            steps=steps + ("Wrote the approved change to disk.",),
        )
    return FixResult(
        target,
        changed=False,
        fixable=True,
        title="Upload guard preview",
        message="Preview only. Apply the fix to write this guarded upload handler.",
        preview=preview,
        steps=steps + ("Stopped before writing because this was a preview.",),
    )


def suggest_or_apply_dependency_fix(
    repo_root: Path,
    relative_file: str,
    title: str,
    recommendation: str,
    write: bool = False,
) -> FixResult:
    target = _resolve_inside(repo_root, relative_file)
    if not target.exists():
        raise FileNotFoundError(f"Fix target not found: {relative_file}")
    if not target.is_file():
        raise IsADirectoryError(f"Fix target is not a file: {relative_file}")
    if not target.name.lower().startswith("requirements") or target.suffix.lower() != ".txt":
        return FixResult(
            target,
            changed=False,
            fixable=False,
            title="No safe dependency fix available",
            message="Dependency auto-fixes currently support requirements*.txt files only.",
            steps=("Checked finding type.", "Refused because the target is not a requirements*.txt file."),
        )

    package_name = _package_from_finding(title, recommendation)
    target_version = _version_from_recommendation(recommendation)
    if not package_name or not target_version:
        return FixResult(
            target,
            changed=False,
            fixable=False,
            title="No safe dependency fix available",
            message="RepoGuard could not identify a package name and fixed version from this finding.",
            steps=("Read the finding recommendation.", "Refused because the package/version was ambiguous."),
        )

    original = target.read_text(encoding="utf-8")
    updated = _patch_requirement(original, package_name, target_version)
    if updated == original:
        return FixResult(
            target,
            changed=False,
            fixable=False,
            title="No safe dependency fix available",
            message=f"RepoGuard could not find one clear requirement line for {package_name}.",
            steps=(
                "Resolved the requirements file inside the selected repository.",
                f"Looked for exactly one editable {package_name} requirement.",
                "Refused to edit because the match was missing or ambiguous.",
            ),
        )

    preview = _build_preview(original, updated, context_lines=4)
    steps = (
        "Resolved the requirements file inside the selected repository.",
        f"Parsed the scanner recommendation for {package_name} -> {target_version}.",
        "Replaced one matching dependency line with a pinned safe version.",
        "Generated a unified diff preview before writing.",
    )
    if write:
        target.write_text(updated, encoding="utf-8")
        return FixResult(
            target,
            changed=True,
            fixable=True,
            title="Dependency update applied",
            message=f"Updated {package_name} to {target_version}.",
            preview=preview,
            steps=steps + ("Wrote the approved change to disk.",),
        )
    return FixResult(
        target,
        changed=False,
        fixable=True,
        title="Dependency update preview",
        message=f"Preview only. Apply the fix to update {package_name} to {target_version}.",
        preview=preview,
        steps=steps + ("Stopped before writing because this was a preview.",),
    )


def suggest_or_apply_license_review_note(repo_root: Path, write: bool = False) -> FixResult:
    root = repo_root.resolve()
    if not root.exists() or not root.is_dir():
        raise NotADirectoryError(f"Repository root not found: {repo_root}")
    for child in root.iterdir():
        if child.is_file() and child.name.lower().startswith("license"):
            return FixResult(
                child,
                changed=False,
                fixable=False,
                title="License already present",
                message="RepoGuard found a top-level license-like file, so it will not add a review note.",
                steps=("Checked the repository root.", "Stopped because a license-like file already exists."),
            )

    target = root / "LICENSE_REVIEW.md"
    if target.exists():
        original = target.read_text(encoding="utf-8")
        if original == LICENSE_REVIEW_NOTE:
            preview = _build_preview(original, original, context_lines=3)
            return FixResult(
                target,
                changed=False,
                fixable=True,
                title="License review note already exists",
                message="No change needed.",
                preview=preview,
                steps=("Checked the repository root.", "Found the existing RepoGuard license review note."),
            )
        return FixResult(
            target,
            changed=False,
            fixable=False,
            title="License review note exists",
            message="LICENSE_REVIEW.md already exists with different content, so RepoGuard will not overwrite it.",
            steps=("Checked the repository root.", "Refused to overwrite an existing review file."),
        )

    preview = _build_preview("", LICENSE_REVIEW_NOTE, context_lines=4)
    steps = (
        "Checked the repository root for a license-like file.",
        "Prepared a LICENSE_REVIEW.md note instead of inventing legal license terms.",
        "Generated a unified diff preview before writing.",
    )
    if write:
        target.write_text(LICENSE_REVIEW_NOTE, encoding="utf-8")
        return FixResult(
            target,
            changed=True,
            fixable=True,
            title="License review note created",
            message="Created LICENSE_REVIEW.md as a reminder to choose a real license.",
            preview=preview,
            steps=steps + ("Wrote the approved note to disk.",),
        )
    return FixResult(
        target,
        changed=False,
        fixable=True,
        title="License review note preview",
        message="Preview only. Apply the fix to create LICENSE_REVIEW.md.",
        preview=preview,
        steps=steps + ("Stopped before writing because this was a preview.",),
    )


def _patch_flask_upload_handler(text: str) -> str:
    if "request.files.getlist" not in text or "file.read()" not in text:
        return text

    updated = text
    if "MAX_UPLOAD_FILES" not in updated:
        marker = "app = Flask(__name__)\n"
        if marker not in updated:
            return text
        updated = updated.replace(marker, marker + UPLOAD_GUARD_HELPER, 1)

    files_line = '    files = request.files.getlist("files")'
    guarded_files = (
        '    files = request.files.getlist("files")\n'
        "    if len(files) > MAX_UPLOAD_FILES:\n"
        '        return {"error": f"Too many files. Max {MAX_UPLOAD_FILES}."}, 413'
    )
    if files_line in updated and "len(files) > MAX_UPLOAD_FILES" not in updated:
        updated = updated.replace(files_line, guarded_files, 1)

    loop_line = "    for file in files:"
    guarded_loop = (
        "    for file in files:\n"
        '        filename = file.filename or ""\n'
        "        if not _allowed_upload_filename(filename):\n"
        '            return {"error": "Unsupported file type."}, 400\n'
        "        data = file.read(MAX_UPLOAD_BYTES + 1)\n"
        "        if len(data) > MAX_UPLOAD_BYTES:\n"
        '            return {"error": f"File too large. Max {MAX_UPLOAD_BYTES} bytes."}, 413'
    )
    if loop_line in updated and "file.read(MAX_UPLOAD_BYTES + 1)" not in updated:
        updated = updated.replace(loop_line, guarded_loop, 1)

    if "file.read(MAX_UPLOAD_BYTES + 1)" in updated:
        updated = updated.replace("file.read()", "data")
    return updated


def _patch_fastapi_upload_handler(text: str) -> str:
    if "UploadFile" not in text or "await upload.read()" not in text:
        return text

    updated = text
    has_count_limit = "len(files) >" in updated
    has_size_limit = "max_bytes" in updated.lower() or "await upload.read(MAX_UPLOAD_BYTES + 1)" in updated
    if "_allowed_upload_filename" not in updated:
        helper = FASTAPI_TYPE_VALIDATION_HELPER if has_count_limit and has_size_limit else FASTAPI_UPLOAD_GUARD_HELPER
        marker = "router = APIRouter"
        marker_index = updated.find(marker)
        if marker_index == -1:
            return text
        line_end = updated.find("\n", marker_index)
        if line_end == -1:
            return text
        updated = updated[: line_end + 1] + helper + updated[line_end + 1 :]

    first_files_check = "    if not files:\n"
    guarded_files = (
        "    if len(files) > MAX_UPLOAD_FILES:\n"
        "        raise HTTPException(\n"
        "            status_code=413,\n"
        "            detail=f\"Too many files in one request (maximum {MAX_UPLOAD_FILES}).\",\n"
        "        )\n\n"
        "    if not files:\n"
    )
    if first_files_check in updated and not has_count_limit:
        updated = updated.replace(first_files_check, guarded_files, 1)

    loop_line = "    for upload in files:\n"
    guarded_loop = (
        "    for upload in files:\n"
        "        if not _allowed_upload_filename(upload.filename):\n"
        "            raise HTTPException(status_code=400, detail=\"Unsupported file type.\")\n"
    )
    if loop_line in updated and "_allowed_upload_filename(upload.filename)" not in updated:
        updated = updated.replace(loop_line, guarded_loop, 1)

    read_line = "        raw_bytes = await upload.read()\n"
    guarded_read = (
        "        raw_bytes = await upload.read(MAX_UPLOAD_BYTES + 1)\n"
        "        if len(raw_bytes) > MAX_UPLOAD_BYTES:\n"
        "            fname = upload.filename or \"upload\"\n"
        "            raise HTTPException(\n"
        "                status_code=413,\n"
        "                detail=f\"File '{fname}' is too large (maximum {MAX_UPLOAD_BYTES // (1024 * 1024)} MB per file).\",\n"
        "            )\n"
    )
    if read_line in updated and not has_size_limit:
        updated = updated.replace(read_line, guarded_read, 1)
    return updated


def _package_from_finding(title: str, recommendation: str) -> str:
    match = re.search(r"Upgrade\s+([A-Za-z0-9_.-]+)\s+to:", recommendation)
    if match:
        return match.group(1).lower()
    return title.split()[0].lower() if title.split() else ""


def _version_from_recommendation(recommendation: str) -> str:
    if "to:" not in recommendation:
        return ""
    version_text = recommendation.split("to:", 1)[1].strip().rstrip(".")
    versions = [item.strip() for item in version_text.split(",") if item.strip()]
    return versions[-1] if versions else ""


def _patch_requirement(text: str, package_name: str, target_version: str) -> str:
    lines = text.splitlines(keepends=True)
    matches: list[int] = []
    pattern = re.compile(rf"^\s*{re.escape(package_name)}\s*(?:==|~=|>=|<=|>|<|=|$)", re.IGNORECASE)
    for index, line in enumerate(lines):
        content = line.split("#", 1)[0].strip()
        if pattern.match(content):
            matches.append(index)
    if len(matches) != 1:
        return text

    index = matches[0]
    line = lines[index]
    newline = "\n" if line.endswith("\n") else ""
    comment = ""
    if "#" in line:
        comment = "  #" + line.split("#", 1)[1].rstrip("\r\n")
    lines[index] = f"{package_name}=={target_version}{comment}{newline}"
    return "".join(lines)


def _resolve_inside(root: Path, relative_file: str) -> Path:
    root = root.resolve()
    target = (root / relative_file).resolve()
    if target != root and root not in target.parents:
        raise PermissionError(f"Fix target escapes repository: {relative_file}")
    return target
