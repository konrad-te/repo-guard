import asyncio
import tempfile
import unittest
from pathlib import Path

from repoguard.execution.runner import GuardedCommandRunner
from repoguard.scanners.filesystem import FilesystemScanner


class FilesystemScannerTests(unittest.TestCase):
    def test_ignores_virtualenv_folders(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app_env = root / ".env"
            app_env.write_text("SECRET=1", encoding="utf-8")
            venv_env = root / "venv" / "Lib" / "site-packages" / "pkg" / ".env"
            venv_env.parent.mkdir(parents=True)
            venv_env.write_text("IGNORE=1", encoding="utf-8")

            scanner = FilesystemScanner()
            result = asyncio.run(scanner.scan(root, GuardedCommandRunner(root)))

            files = {finding.file for finding in result.findings}
            self.assertIn(".env", files)
            self.assertNotIn("venv\\Lib\\site-packages\\pkg\\.env", files)


if __name__ == "__main__":
    unittest.main()
