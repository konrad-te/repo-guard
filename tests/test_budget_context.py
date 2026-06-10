import unittest

from repoguard.orchestrator.budget import BudgetExceeded, TokenBudget
from repoguard.orchestrator.context import compress_output, redact_secrets


class BudgetContextTests(unittest.TestCase):
    def test_budget_warns_and_caps(self):
        budget = TokenBudget(
            max_context_tokens=10,
            hard_token_cap=12,
            warn_ratio=0.5,
            budget_usd=100,
            input_cost_per_1k=1,
            output_cost_per_1k=1,
        )
        budget.add_context("small", "x" * 20)
        self.assertTrue(budget.warnings)
        with self.assertRaises(BudgetExceeded):
            budget.add_context("too-big", "x" * 100)

    def test_compress_output_keeps_important_lines(self):
        text = ("normal line\n" * 1000) + "CRITICAL secret issue at app.py:10\n" + ("tail\n" * 1000)
        compressed = compress_output(text, max_chars=1000)
        self.assertIn("CRITICAL secret issue", compressed)
        self.assertLessEqual(len(compressed), 1100)

    def test_redacts_secret_like_values(self):
        redacted = redact_secrets("api_key = abcdefghijklmnopqrstuvwxyz")
        self.assertIn("REDACTED", redacted)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", redacted)


if __name__ == "__main__":
    unittest.main()
