import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from repoguard.execution.runner import GuardedCommandRunner


class GuardedCommandRunnerTests(unittest.IsolatedAsyncioTestCase):
    async def test_uses_resolved_executable_path(self):
        calls = []

        def fake_run(*args, **kwargs):
            calls.append((args, kwargs))
            return SimpleNamespace(returncode=0, stdout=b"ok", stderr=b"")

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            resolved = r"C:\Program Files\Git\cmd\git.exe"
            runner = GuardedCommandRunner(root)

            with patch("shutil.which", return_value=resolved), patch("subprocess.run", side_effect=fake_run):
                result = await runner.run(["git", "clone", "--depth", "1", "https://github.com/a/b", str(root / "b")])

        self.assertEqual(result.exit_code, 0)
        self.assertEqual(calls[0][0][0][0], resolved)
        self.assertEqual(calls[0][0][0][1:4], ["clone", "--depth", "1"])


if __name__ == "__main__":
    unittest.main()
