import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from repoguard.config import RepoGuardConfig


class ConfigTests(unittest.TestCase):
    def test_loads_non_secret_settings_from_toml(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "repoguard.toml"
            path.write_text(
                """
[scan]
report_dir = "custom-reports"
max_concurrency = 2
fail_on_severity = "medium"

[budget]
max_context_tokens = 100
hard_token_cap = 120
budget_usd = 0.25

[ai]
enabled = false
model = "test-model"
""",
                encoding="utf-8",
            )

            with patch("repoguard.config.load_dotenv"):
                config = RepoGuardConfig.from_env(path)

            self.assertEqual(config.report_dir, Path("custom-reports"))
            self.assertEqual(config.max_concurrency, 2)
            self.assertEqual(config.fail_on_severity, "medium")
            self.assertEqual(config.max_context_tokens, 100)
            self.assertEqual(config.hard_token_cap, 120)
            self.assertEqual(config.budget_usd, 0.25)
            self.assertFalse(config.ai_enabled)
            self.assertEqual(config.gemini_model, "test-model")

    def test_environment_overrides_config_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "repoguard.toml"
            path.write_text(
                """
[scan]
max_concurrency = 2
""",
                encoding="utf-8",
            )
            previous = os.environ.get("MAX_CONCURRENCY")
            os.environ["MAX_CONCURRENCY"] = "9"
            try:
                with patch("repoguard.config.load_dotenv"):
                    config = RepoGuardConfig.from_env(path)
            finally:
                if previous is None:
                    os.environ.pop("MAX_CONCURRENCY", None)
                else:
                    os.environ["MAX_CONCURRENCY"] = previous

            self.assertEqual(config.max_concurrency, 9)

    def test_float_environment_settings_are_parsed(self):
        with patch("repoguard.config.load_dotenv"), patch.dict(
            os.environ,
            {
                "WARN_TOKEN_RATIO": "0.75",
                "BUDGET_USD": "2.25",
                "INPUT_COST_PER_1K": "0.1",
                "OUTPUT_COST_PER_1K": "0.2",
            },
            clear=False,
        ):
            config = RepoGuardConfig.from_env()

        self.assertEqual(config.warn_token_ratio, 0.75)
        self.assertEqual(config.budget_usd, 2.25)
        self.assertEqual(config.input_cost_per_1k, 0.1)
        self.assertEqual(config.output_cost_per_1k, 0.2)


if __name__ == "__main__":
    unittest.main()
