from __future__ import annotations

import os
import tomllib
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


def _bool_env(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if not value:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _read_config_file(path: Path | None) -> dict:
    if path is None:
        default_path = Path(os.environ.get("REPOGUARD_CONFIG", "repoguard.toml"))
        path = default_path if default_path.exists() else None
    if path is None:
        return {}
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _config_value(config: dict, section: str, key: str, default):
    section_data = config.get(section, {})
    if not isinstance(section_data, dict):
        return default
    return section_data.get(key, default)


def _int_setting(config: dict, section: str, key: str, env_name: str, default: int) -> int:
    file_value = _config_value(config, section, key, default)
    return _int_env(env_name, int(file_value))


def _float_setting(config: dict, section: str, key: str, env_name: str, default: float) -> float:
    file_value = _config_value(config, section, key, default)
    return _float_env(env_name, float(file_value))


def _str_setting(config: dict, section: str, key: str, env_name: str, default: str) -> str:
    file_value = _config_value(config, section, key, default)
    return os.environ.get(env_name, str(file_value))


def _bool_setting(config: dict, section: str, key: str, env_name: str, default: bool) -> bool:
    file_value = bool(_config_value(config, section, key, default))
    return _bool_env(env_name, file_value)


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
    gemini_api_key: str | None
    gemini_model: str
    fail_on_severity: str
    ai_enabled: bool = True

    @classmethod
    def from_env(cls, config_path: Path | None = None) -> "RepoGuardConfig":
        load_dotenv()
        config = _read_config_file(config_path)
        return cls(
            report_dir=Path(_str_setting(config, "scan", "report_dir", "REPORT_DIR", "reports")),
            scanner_timeout_seconds=_int_setting(config, "scan", "scanner_timeout_seconds", "SCANNER_TIMEOUT_SECONDS", 300),
            max_output_bytes=_int_setting(config, "scan", "max_output_bytes", "MAX_OUTPUT_BYTES", 1_048_576),
            max_concurrency=_int_setting(config, "scan", "max_concurrency", "MAX_CONCURRENCY", 5),
            max_context_tokens=_int_setting(config, "budget", "max_context_tokens", "MAX_CONTEXT_TOKENS", 120_000),
            warn_token_ratio=_float_setting(config, "budget", "warn_token_ratio", "WARN_TOKEN_RATIO", 0.8),
            hard_token_cap=_int_setting(config, "budget", "hard_token_cap", "HARD_TOKEN_CAP", 150_000),
            budget_usd=_float_setting(config, "budget", "budget_usd", "BUDGET_USD", 1.5),
            input_cost_per_1k=_float_setting(config, "budget", "input_cost_per_1k", "INPUT_COST_PER_1K", 0.0),
            output_cost_per_1k=_float_setting(config, "budget", "output_cost_per_1k", "OUTPUT_COST_PER_1K", 0.0),
            gemini_api_key=os.environ.get("GEMINI_API_KEY") or None,
            gemini_model=_str_setting(config, "ai", "model", "GEMINI_MODEL", "gemini-3.5-flash"),
            fail_on_severity=_str_setting(config, "scan", "fail_on_severity", "FAIL_ON_SEVERITY", "high").lower(),
            ai_enabled=_bool_setting(config, "ai", "enabled", "AI_ENABLED", True),
        )
