from __future__ import annotations

import re
from pathlib import Path

from repoguard.execution.runner import GuardedCommandRunner
from repoguard.models import AgentStatus, Finding, ScannerResult, Severity
from repoguard.scanners.base import ScannerAgent


CODE_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".go",
    ".rb",
    ".php",
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
    ".env",
    "node_modules",
    "dist",
    "build",
    "reports",
}

UPLOAD_MARKERS = (
    "request.files",
    "uploadfile",
    "multipart",
    "multer",
    "formidable",
    "busboy",
    "filefield",
    "fileupload",
    "uploaded_file",
    "upload_file",
)

SIZE_LIMIT_MARKERS = (
    "max_content_length",
    "max_bytes",
    "max_file_size",
    "max_upload_bytes",
    "file_size_limit",
    "content_length",
    "content-length",
    "filesize",
    "file_size",
    "limits:",
    "fileSize",
)

COUNT_LIMIT_MARKERS = (
    "max_files",
    "maxfiles",
    "max_file_count",
    "max_upload_files",
    "array(",
    "maxcount",
    "max_count",
)

COUNT_LIMIT_PATTERNS = (
    re.compile(r"len\(\s*files\s*\)\s*(>|>=)\s*\d+", re.IGNORECASE),
    re.compile(r"len\(\s*request\.files[^)]*\)\s*(>|>=)\s*\d+", re.IGNORECASE),
    re.compile(r"files\.length\s*(>|>=)\s*\d+", re.IGNORECASE),
    re.compile(r"getlist\([^)]*\)\s*\[:\s*\d+\s*\]", re.IGNORECASE),
    re.compile(r"in\s+\w+\s*\[:\s*\d+\s*\]", re.IGNORECASE),
)

TYPE_VALIDATION_MARKERS = (
    "allowed_extensions",
    "allowed_file",
    "mimetype",
    "mime",
    "content_type",
    "content-type",
    "secure_filename",
    "filetype",
    "extension",
)

DATABASE_STORAGE_MARKERS = (
    "largebinary",
    "blob",
    "bytea",
    "db.session.add",
    ".insert_one(",
    ".insert(",
    "prisma.",
    "save(",
)


class UploadSecurityScanner(ScannerAgent):
    name = "upload-risk-agent"
    description = "Heuristic scanner for unsafe file upload handlers."

    async def scan(self, repo_path: Path, runner: GuardedCommandRunner) -> ScannerResult:
        result = ScannerResult(name=self.name, status=AgentStatus.COMPLETE)
        inspected = 0
        upload_files = 0
        for path in repo_path.rglob("*"):
            if any(part in IGNORED_DIRS for part in path.parts) or not path.is_file():
                continue
            if path.suffix.lower() not in CODE_SUFFIXES:
                continue
            inspected += 1
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lower = text.lower()
            if not any(marker in lower for marker in UPLOAD_MARKERS):
                continue
            upload_files += 1
            relative = str(path.relative_to(repo_path))
            line_no, evidence = _first_matching_line(text, UPLOAD_MARKERS)
            has_size_limit = any(marker.lower() in lower for marker in SIZE_LIMIT_MARKERS)
            has_count_limit = (
                any(marker.lower() in lower for marker in COUNT_LIMIT_MARKERS)
                or any(pattern.search(text) for pattern in COUNT_LIMIT_PATTERNS)
            )
            has_type_validation = any(marker.lower() in lower for marker in TYPE_VALIDATION_MARKERS)
            stores_binary = any(marker.lower() in lower for marker in DATABASE_STORAGE_MARKERS)

            if not has_size_limit or not has_count_limit:
                missing = []
                if not has_size_limit:
                    missing.append("file size limit")
                if not has_count_limit:
                    missing.append("file count limit")
                result.findings.append(
                    Finding(
                        scanner=self.name,
                        title="Upload handler has no obvious resource limit",
                        severity=Severity.HIGH,
                        file=relative,
                        line=line_no,
                        description=(
                            "The file appears to accept uploads, but RepoGuard did not find an obvious "
                            f"{' or '.join(missing)}. This can allow users to exhaust storage, memory, "
                            "or database capacity with large or repeated uploads."
                        ),
                        recommendation=(
                            "Add explicit max file size and max file count checks before reading or storing files. "
                            "Reject the request early with a clear error when limits are exceeded."
                        ),
                        evidence=evidence,
                        rule_id="upload.unbounded-resource-use",
                        confidence="medium",
                    )
                )

            if not has_type_validation:
                result.findings.append(
                    Finding(
                        scanner=self.name,
                        title="Upload handler has no obvious file type validation",
                        severity=Severity.MEDIUM,
                        file=relative,
                        line=line_no,
                        description=(
                            "The file appears to accept uploads, but RepoGuard did not find an obvious MIME type, "
                            "extension, or filename validation step."
                        ),
                        recommendation=(
                            "Validate file type with an allowlist and normalize filenames before storing files."
                        ),
                        evidence=evidence,
                        rule_id="upload.missing-type-validation",
                        confidence="medium",
                    )
                )

            if stores_binary and not has_size_limit:
                result.findings.append(
                    Finding(
                        scanner=self.name,
                        title="Uploaded data may be stored without size limits",
                        severity=Severity.HIGH,
                        file=relative,
                        line=line_no,
                        description=(
                            "The upload path contains database/storage keywords and no obvious size limit. "
                            "Storing unbounded upload data can rapidly exhaust database or object storage."
                        ),
                        recommendation=(
                            "Set per-file and per-user quotas before storage, and prefer object storage with quotas "
                            "over writing arbitrary binary data directly into the database."
                        ),
                        evidence=evidence,
                        rule_id="upload.unbounded-storage",
                        confidence="low",
                    )
                )

        result.summary = (
            f"Inspected {inspected} source files and found {upload_files} file(s) with upload-related code."
        )
        result.compressed_output = result.summary
        return result.finish()


def _first_matching_line(text: str, markers: tuple[str, ...]) -> tuple[int | None, str]:
    lowered_markers = tuple(marker.lower() for marker in markers)
    for line_no, line in enumerate(text.splitlines(), start=1):
        lower = line.lower()
        if any(marker in lower for marker in lowered_markers):
            return line_no, line.strip()[:500]
    return None, ""
