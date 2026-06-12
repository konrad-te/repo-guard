import tempfile
import unittest
from pathlib import Path

from repoguard.editing.fixes import (
    suggest_or_apply_dependency_fix,
    suggest_or_apply_license_review_note,
    suggest_or_apply_upload_fix,
)


VULNERABLE_APP = '''from flask import Flask, request

app = Flask(__name__)

DATABASE_ROWS = []


@app.post("/upload")
def upload():
    files = request.files.getlist("files")
    for file in files:
        DATABASE_ROWS.append({
            "filename": file.filename,
            "data": file.read(),
        })
    return {"saved": len(files)}
'''

VULNERABLE_FASTAPI_APP = '''from fastapi import APIRouter, File, UploadFile

router = APIRouter(prefix="/api/demo")


@router.post("/import")
async def import_files(files: list[UploadFile] = File(...)):
    if not files:
        return {"error": "choose files"}

    saved = 0
    for upload in files:
        raw_bytes = await upload.read()
        saved += len(raw_bytes)
    return {"saved": saved}
'''

FASTAPI_WITH_RESOURCE_LIMITS_ONLY = '''from fastapi import APIRouter, File, HTTPException, UploadFile

router = APIRouter(prefix="/api/demo")


def app_upload_max_files() -> int:
    return 10


def app_upload_max_bytes() -> int:
    return 5 * 1024 * 1024


@router.post("/import")
async def import_files(files: list[UploadFile] = File(...)):
    if not files:
        raise HTTPException(status_code=400, detail="Choose files.")

    max_files = app_upload_max_files()
    if len(files) > max_files:
        raise HTTPException(status_code=400, detail="Too many files.")

    max_bytes = app_upload_max_bytes()
    for upload in files:
        raw_bytes = await upload.read()
        if len(raw_bytes) > max_bytes:
            raise HTTPException(status_code=413, detail="Too large.")
    return {"ok": True}
'''


class FixSuggestionTests(unittest.TestCase):
    def test_upload_fix_preview_does_not_write(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "app.py"
            target.write_text(VULNERABLE_APP, encoding="utf-8")

            result = suggest_or_apply_upload_fix(root, "app.py")

            self.assertTrue(result.fixable)
            self.assertFalse(result.changed)
            self.assertIn("MAX_UPLOAD_FILES", result.preview)
            self.assertNotIn("MAX_UPLOAD_FILES", target.read_text(encoding="utf-8"))

    def test_upload_fix_write_applies_guard(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "app.py"
            target.write_text(VULNERABLE_APP, encoding="utf-8")

            result = suggest_or_apply_upload_fix(root, "app.py", write=True)
            updated = target.read_text(encoding="utf-8")

            self.assertTrue(result.changed)
            self.assertIn("MAX_UPLOAD_FILES", updated)
            self.assertIn("MAX_UPLOAD_BYTES", updated)
            self.assertIn("_allowed_upload_filename", updated)
            self.assertIn('"data": data,', updated)

    def test_fastapi_upload_fix_preview(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "router.py"
            target.write_text(VULNERABLE_FASTAPI_APP, encoding="utf-8")

            result = suggest_or_apply_upload_fix(root, "router.py")

            self.assertTrue(result.fixable)
            self.assertIn("MAX_UPLOAD_FILES", result.preview)

    def test_fastapi_upload_fix_write_applies_guard(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "router.py"
            target.write_text(VULNERABLE_FASTAPI_APP, encoding="utf-8")

            result = suggest_or_apply_upload_fix(root, "router.py", write=True)
            updated = target.read_text(encoding="utf-8")

            self.assertTrue(result.changed)
            self.assertIn("MAX_UPLOAD_FILES", updated)
            self.assertIn("MAX_UPLOAD_BYTES", updated)
            self.assertIn("_allowed_upload_filename(upload.filename)", updated)

    def test_fastapi_upload_fix_adds_type_validation_when_resource_limits_exist(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "router.py"
            target.write_text(FASTAPI_WITH_RESOURCE_LIMITS_ONLY, encoding="utf-8")

            result = suggest_or_apply_upload_fix(root, "router.py", write=True)
            updated = target.read_text(encoding="utf-8")

            self.assertTrue(result.changed)
            self.assertIn("_allowed_upload_filename(upload.filename)", updated)
            self.assertIn("Unsupported file type", updated)
            self.assertIn("if len(files) > max_files:", updated)
            self.assertIn("if len(raw_bytes) > max_bytes:", updated)

    def test_refuses_path_escape(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "repo"
            root.mkdir()

            with self.assertRaises(PermissionError):
                suggest_or_apply_upload_fix(root, "../outside.py")

    def test_dependency_fix_preview_does_not_write(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "requirements.txt"
            target.write_text("Flask==0.12\nrequests==2.32.0\n", encoding="utf-8")

            result = suggest_or_apply_dependency_fix(
                root,
                "requirements.txt",
                "flask PYSEC-2023-62",
                "Upgrade flask to: 2.2.5, 2.3.2.",
            )

            self.assertTrue(result.fixable)
            self.assertFalse(result.changed)
            self.assertIn("flask==2.3.2", result.preview)
            self.assertIn("Flask==0.12", target.read_text(encoding="utf-8"))

    def test_dependency_fix_write_updates_one_requirement(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "requirements.txt"
            target.write_text("Flask==0.12\nrequests==2.32.0\n", encoding="utf-8")

            result = suggest_or_apply_dependency_fix(
                root,
                "requirements.txt",
                "flask CVE-2026-27205",
                "Upgrade flask to: 3.1.3.",
                write=True,
            )

            self.assertTrue(result.changed)
            updated = target.read_text(encoding="utf-8")
            self.assertIn("flask==3.1.3", updated)
            self.assertIn("requests==2.32.0", updated)

    def test_license_review_note_preview_does_not_write(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            result = suggest_or_apply_license_review_note(root)

            self.assertTrue(result.fixable)
            self.assertFalse(result.changed)
            self.assertEqual(result.file.name, "LICENSE_REVIEW.md")
            self.assertIn("License Review Needed", result.preview)
            self.assertFalse((root / "LICENSE_REVIEW.md").exists())

    def test_license_review_note_write_creates_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            result = suggest_or_apply_license_review_note(root, write=True)

            self.assertTrue(result.changed)
            self.assertTrue((root / "LICENSE_REVIEW.md").exists())
            self.assertIn("not a legal license", (root / "LICENSE_REVIEW.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
