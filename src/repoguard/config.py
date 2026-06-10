from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def load_dotenv(path: Path = Path(".env")) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _int_env(name: str, default: int) -> int:
    value = os.environ.get(name)
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _float_env(name: str, default: float) -> float:
    value = os.environ.get(name)
    if not value:
        return default
    try:
        return float(value)
    except ValueError:
        return default


@dataclass(slots=True)
class RepoGuardConfig:
    report_dir: Path
    scanner_timeout_seconds: int
    max_output_bytes: int
    max_concurrency: int
    max_context_tokens: int
    warn_token_ratio: float
    hard_token_cap: int
    budget_usd: float
    input_cost_per_1k: float
    output_cost_per_1k: float
    openai_api_key: str | None
    openai_model: str
    fail_on_severity: str
    ai_enabled: bool = True

    @classmethod
    def from_env(cls) -> "RepoGuardConfig":
        load_dotenv()
        return cls(
            report_dir=Path(os.environ.get("REPORT_DIR", "reports")),
            scanner_timeout_seconds=_int_env("SCANNER_TIMEOUT_SECONDS", 300),
            max_output_bytes=_int_env("MAX_OUTPUT_BYTES", 1_048_576),
            max_concurrency=_int_env("MAX_CONCURRENCY", 5),
            max_context_tokens=_int_env("MAX_CONTEXT_TOKENS", 120_000),
            warn_token_ratio=_float_env("WARN_TOKEN_RATIO", 0.8),
            hard_token_cap=_int_env("HARD_TOKEN_CAP", 150_000),
            budget_usd=_float_env("BUDGET_USD", 1.5),
            input_cost_per_1k=_float_env("INPUT_COST_PER_1K", 0.0004),
            output_cost_per_1k=_float_env("OUTPUT_COST_PER_1K", 0.0016),
            openai_api_key=os.environ.get("OPENAI_API_KEY") or None,
            openai_model=os.environ.get("OPENAI_MODEL", "gpt-4.1-mini"),
            fail_on_severity=os.environ.get("FAIL_ON_SEVERITY", "high").lower(),
        )
