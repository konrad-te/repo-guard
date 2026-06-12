import asyncio
import tempfile
import unittest
from pathlib import Path

from repoguard.execution.runner import GuardedCommandRunner
from repoguard.editing.fixes import suggest_or_apply_upload_fix
from repoguard.scanners.upload_security import UploadSecurityScanner


class UploadSecurityScannerTests(unittest.TestCase):
    def test_flags_unbounded_upload_handler(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app = root / "app.py"
            app.write_text(
                """
from flask import Flask, request

app = Flask(__name__)

@app.post("/upload")
def upload():
    files = request.files.getlist("files")
    for file in files:
        db.session.add(file.read())
    return "ok"
""",
                encoding="utf-8",
            )
            scanner = UploadSecurityScanner()
            result = asyncio.run(scanner.scan(root, GuardedCommandRunner(root)))

            titles = {finding.title for finding in result.findings}
            self.assertIn("Upload handler has no obvious resource limit", titles)
            self.assertIn("Upload handler has no obvious file type validation", titles)

    def test_limited_upload_handler_is_not_flagged_for_resource_limit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app = root / "app.py"
            app.write_text(
                """
from flask import Flask, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
ALLOWED_EXTENSIONS = {"png", "jpg"}

@app.post("/upload")
def upload():
    files = request.files.getlist("files")
    if len(files) > 5:
        return "too many", 413
    return "ok"
""",
                encoding="utf-8",
            )
            scanner = UploadSecurityScanner()
            result = asyncio.run(scanner.scan(root, GuardedCommandRunner(root)))

            titles = {finding.title for finding in result.findings}
            self.assertNotIn("Upload handler has no obvious resource limit", titles)

    def test_sliced_upload_list_counts_as_count_limit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app = root / "app.py"
            app.write_text(
                """
from flask import Flask, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024

@app.post("/upload")
def upload():
    files = request.files.getlist("files")[:10]
    return "ok"
""",
                encoding="utf-8",
            )
            scanner = UploadSecurityScanner()
            result = asyncio.run(scanner.scan(root, GuardedCommandRunner(root)))

            resource_findings = [
                finding
                for finding in result.findings
                if finding.rule_id == "upload.unbounded-resource-use"
            ]
            self.assertFalse(resource_findings)

    def test_sliced_upload_loop_counts_as_count_limit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app = root / "app.py"
            app.write_text(
                """
from flask import Flask, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024

@app.post("/upload")
def upload():
    files = request.files.getlist("files")
    for file in files[:10]:
        pass
    return "ok"
""",
                encoding="utf-8",
            )
            scanner = UploadSecurityScanner()
            result = asyncio.run(scanner.scan(root, GuardedCommandRunner(root)))

            resource_findings = [
                finding
                for finding in result.findings
                if finding.rule_id == "upload.unbounded-resource-use"
            ]
            self.assertFalse(resource_findings)

    def test_custom_max_files_and_max_bytes_helpers_count_as_resource_limits(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app = root / "router.py"
            app.write_text(
                """
from fastapi import File, UploadFile

async def import_files(files: list[UploadFile] = File(...)):
    max_files = app_upload_max_files()
    if len(files) > max_files:
        raise ValueError("too many")

    max_bytes = app_upload_max_bytes()
    for upload in files:
        raw_bytes = await upload.read()
        if len(raw_bytes) > max_bytes:
            raise ValueError("too large")
    return "ok"
""",
                encoding="utf-8",
            )
            scanner = UploadSecurityScanner()
            result = asyncio.run(scanner.scan(root, GuardedCommandRunner(root)))

            rule_ids = {finding.rule_id for finding in result.findings}
            self.assertNotIn("upload.unbounded-resource-use", rule_ids)

    def test_repo_guard_upload_fix_is_recognized_on_rescan(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app = root / "app.py"
            app.write_text(
                """
from flask import Flask, request

app = Flask(__name__)

@app.post("/upload")
def upload():
    files = request.files.getlist("files")
    for file in files:
        db.session.add(file.read())
    return "ok"
""",
                encoding="utf-8",
            )
            suggest_or_apply_upload_fix(root, "app.py", write=True)

            scanner = UploadSecurityScanner()
            result = asyncio.run(scanner.scan(root, GuardedCommandRunner(root)))
            rule_ids = {finding.rule_id for finding in result.findings}

            self.assertNotIn("upload.unbounded-resource-use", rule_ids)
            self.assertNotIn("upload.missing-type-validation", rule_ids)


if __name__ == "__main__":
    unittest.main()
