from __future__ import annotations

import asyncio
import json

from repoguard.models import ScanReport, SEVERITY_ORDER
from repoguard.orchestrator.budget import BudgetExceeded, TokenBudget
from repoguard.orchestrator.context import compact_json


class ReportAgent:
    async def enrich(self, report: ScanReport, budget: TokenBudget) -> None:
        raise NotImplementedError


class HeuristicReportAgent(ReportAgent):
    async def enrich(self, report: ScanReport, budget: TokenBudget) -> None:
        findings = sorted(
            report.all_findings(),
            key=lambda finding: SEVERITY_ORDER[finding.severity],
            reverse=True,
        )
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_severity[finding.severity.value] = by_severity.get(finding.severity.value, 0) + 1
        budget.add_context("heuristic-report-agent", compact_json(report.to_dict(), max_chars=8_000))
        if findings:
            top = findings[0]
            report.summary = (
                f"RepoGuard found {len(findings)} issue(s). Highest risk is {top.severity.value}: {top.title}."
            )
        else:
            report.summary = "RepoGuard did not find scanner-backed security issues in this run."
        report.recommendations = [
            "Do not execute installation scripts or project entrypoints until high and critical findings are reviewed.",
            "Rotate any credential reported by the secret scanner, even if the detector marked it unverified.",
            "Pin or upgrade vulnerable dependencies before building the project.",
            "Keep raw scanner artifacts local; share the redacted Markdown/JSON report instead.",
        ]
        if by_severity:
            report.recommendations.insert(0, f"Finding distribution: {by_severity}.")


class GeminiReportAgent(ReportAgent):
    def __init__(self, api_key: str, model: str) -> None:
        self.api_key = api_key
        self.model = model

    async def enrich(self, report: ScanReport, budget: TokenBudget) -> None:
        payload = compact_json(report.to_dict(), max_chars=12_000)
        budget.add_context("gemini-report-agent-input", payload)
        prompt = (
            "You are RepoGuard's final security reporting agent. "
            "Use only scanner-backed facts. Return compact JSON only with keys summary and recommendations. "
            "recommendations must be an array of short strings. Do not include raw secrets.\n\n"
            f"{payload}"
        )
        try:
            response_text = await self._call_gemini_with_retries(prompt)
            budget.add_model_usage(0, max(1, len(response_text) // 4))
            data = json.loads(_strip_json_fence(response_text))
            if isinstance(data.get("summary"), str):
                report.summary = data["summary"]
            if isinstance(data.get("recommendations"), list):
                report.recommendations = [str(item) for item in data["recommendations"][:10]]
        except BudgetExceeded:
            raise
        except (ImportError, json.JSONDecodeError, Exception) as exc:
            fallback = HeuristicReportAgent()
            await fallback.enrich(report, budget)
            detail = str(exc).replace(self.api_key, "[redacted]")[:160]
            report.recommendations.append(f"AI enrichment fallback used: {type(exc).__name__}: {detail}")

    async def _call_gemini_with_retries(self, prompt: str) -> str:
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                return await asyncio.to_thread(self._call_gemini, prompt)
            except Exception as exc:
                last_error = exc
                transient = type(exc).__name__ in {"ServerError", "ConnectError", "TimeoutException"}
                if not transient or attempt == 2:
                    break
                await asyncio.sleep(0.8 * (attempt + 1))
        if last_error:
            raise last_error
        return "{}"

    def _call_gemini(self, prompt: str) -> str:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=self.api_key)
        response = client.models.generate_content(
            model=self.model,
            contents=prompt,
            config=types.GenerateContentConfig(response_mime_type="application/json"),
        )
        return response.text or "{}"


def _strip_json_fence(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```json"):
        stripped = stripped.removeprefix("```json").strip()
    elif stripped.startswith("```"):
        stripped = stripped.removeprefix("```").strip()
    if stripped.endswith("```"):
        stripped = stripped.removesuffix("```").strip()
    return stripped
