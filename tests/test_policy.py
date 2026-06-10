from pathlib import Path
import unittest

from repoguard.execution.policy import ExecutionPolicy


class ExecutionPolicyTests(unittest.TestCase):
    def test_blocks_shell_metacharacters(self):
        policy = ExecutionPolicy()
        with self.assertRaises(PermissionError):
            policy.validate(["bandit", "-r", ".", "&&", "rm", "-rf", "/"], Path.cwd(), Path.cwd())

    def test_blocks_unknown_binary(self):
        policy = ExecutionPolicy()
        with self.assertRaises(PermissionError):
            policy.validate(["bash", "-lc", "echo nope"], Path.cwd(), Path.cwd())

    def test_allows_scanner_inside_workspace(self):
        import tempfile

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            nested = root / "repo"
            nested.mkdir()
            policy = ExecutionPolicy()
            policy.validate(["bandit", "-r", str(nested), "-f", "json"], nested, root)


if __name__ == "__main__":
    unittest.main()
