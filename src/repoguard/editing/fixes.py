from __future__ import annotations

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
        )

    preview = _build_preview(original, updated, context_lines=5)
    if write:
        target.write_text(updated, encoding="utf-8")
        return FixResult(
            target,
            changed=True,
            fixable=True,
            title="Upload guard applied",
            message="Added upload count, size, and extension checks.",
            preview=preview,
        )
    return FixResult(
        target,
        changed=False,
        fixable=True,
        title="Upload guard preview",
        message="Preview only. Apply the fix to write this guarded upload handler.",
        preview=preview,
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


def _resolve_inside(root: Path, relative_file: str) -> Path:
    root = root.resolve()
    target = (root / relative_file).resolve()
    if target != root and root not in target.parents:
        raise PermissionError(f"Fix target escapes repository: {relative_file}")
    return target
