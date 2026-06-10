import unittest

from repoguard.ai.report_agent import _strip_json_fence


class ReportAgentTests(unittest.TestCase):
    def test_strips_json_markdown_fence(self):
        text = '```json\n{"summary": "ok", "recommendations": []}\n```'

        self.assertEqual(_strip_json_fence(text), '{"summary": "ok", "recommendations": []}')


if __name__ == "__main__":
    unittest.main()
