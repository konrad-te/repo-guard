import tempfile
import unittest
from pathlib import Path

from repoguard.editing.patcher import apply_exact_replacement


class PatcherTests(unittest.TestCase):
    def test_dry_run_does_not_write(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "app.py"
            target.write_text("limit = None\n", encoding="utf-8")

            result = apply_exact_replacement(root, "app.py", "limit = None", "limit = 10")

            self.assertFalse(result.changed)
            self.assertIn("Dry run", result.message)
            self.assertEqual(target.read_text(encoding="utf-8"), "limit = None\n")
            self.assertIn("limit = 10", result.preview)

    def test_write_applies_single_exact_replacement(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "app.py"
            target.write_text("limit = None\n", encoding="utf-8")

            result = apply_exact_replacement(root, "app.py", "limit = None", "limit = 10", write=True)

            self.assertTrue(result.changed)
            self.assertEqual(target.read_text(encoding="utf-8"), "limit = 10\n")

    def test_refuses_ambiguous_replacement(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "app.py"
            target.write_text("x = 1\nx = 1\n", encoding="utf-8")

            result = apply_exact_replacement(root, "app.py", "x = 1", "x = 2", write=True)

            self.assertFalse(result.changed)
            self.assertIn("multiple times", result.message)
            self.assertEqual(target.read_text(encoding="utf-8"), "x = 1\nx = 1\n")

    def test_refuses_path_escape(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "repo"
            root.mkdir()

            with self.assertRaises(PermissionError):
                apply_exact_replacement(root, "../outside.py", "x", "y")


if __name__ == "__main__":
    unittest.main()
