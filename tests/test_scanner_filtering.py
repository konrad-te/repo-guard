import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from repoguard.models import CommandResult
from repoguard.scanners.paths import is_excluded_path
from repoguard.scanners.pip_audit import PipAuditScanner
from repoguard.scanners.trufflehog import TruffleHogScanner


class FakeRunner:
    def __init__(self, stdout: str):
        self.stdout = stdout

    async def run(self, command, cwd=None):
        return CommandResult(command=list(command), cwd=str(cwd), exit_code=1, stdout=self.stdout)


class ScannerFilteringTests(unittest.TestCase):
    def test_excluded_path_detects_vendor_folders(self):
        self.assertTrue(is_excluded_path("frontend/node_modules/pkg/index.js"))
        self.assertTrue(is_excluded_path("backend/venv/Lib/site-packages/pkg.py"))
        self.assertFalse(is_excluded_path("backend/routers/sleep.py"))

    def test_trufflehog_skips_vendor_and_duplicate_matches(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app_file = root / "backend" / "settings.py"
            vendor_file = root / "frontend" / "node_modules" / "pkg" / "test.js"
            lines = [
                _trufflehog_line("MongoDB", app_file, 4),
                _trufflehog_line("MongoDB", app_file, 4),
                _trufflehog_line("MongoDB", vendor_file, 9),
            ]

            result = asyncio.run(TruffleHogScanner().scan(root, FakeRunner("\n".join(lines))))

            self.assertEqual(len(result.findings), 1)
            self.assertEqual(result.findings[0].file, str(app_file))
            self.assertIn("Skipped 2", result.summary)

    def test_pip_audit_skips_vendor_requirements_and_duplicate_advisories(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            req = root / "requirements.txt"
            req.write_text("requests==2.0.0", encoding="utf-8")
            vendor_req = root / "venv" / "requirements.txt"
            vendor_req.parent.mkdir()
            vendor_req.write_text("ignored==1.0.0", encoding="utf-8")
            payload = {
                "dependencies": [
                    {
                        "name": "requests",
                        "vulns": [
                            {"id": "CVE-1", "aliases": ["GHSA-1"], "fix_versions": ["2.1.0"], "description": "a"},
                            {"id": "CVE-1", "aliases": ["GHSA-1"], "fix_versions": ["2.1.0"], "description": "b"},
                        ],
                    }
                ]
            }

            result = asyncio.run(PipAuditScanner().scan(root, FakeRunner(json.dumps(payload))))

            self.assertEqual(len(result.findings), 1)
            self.assertEqual(result.findings[0].file, str(req))
            self.assertIn("Skipped 1 duplicate", result.summary)


def _trufflehog_line(detector: str, file_path: Path, line: int) -> str:
    return json.dumps(
        {
            "DetectorName": detector,
            "Verified": False,
            "SourceMetadata": {
                "Data": {
                    "Filesystem": {
                        "file": str(file_path),
                        "line": line,
                    }
                }
            },
        }
    )


if __name__ == "__main__":
    unittest.main()
