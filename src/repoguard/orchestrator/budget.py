from __future__ import annotations

from dataclasses import dataclass, field

from repoguard.models import BudgetSnapshot


class BudgetExceeded(RuntimeError):
    pass


def estimate_tokens(text: str) -> int:
    if not text:
        return 0
    return max(1, (len(text) + 3) // 4)


@dataclass(slots=True)
class TokenBudget:
    max_context_tokens: int
    hard_token_cap: int
    warn_ratio: float
    budget_usd: float
    input_cost_per_1k: float
    output_cost_per_1k: float
    used_tokens: int = 0
    estimated_cost_usd: float = 0.0
    warnings: list[str] = field(default_factory=list)
    capped: bool = False

    def __post_init__(self) -> None:
        if self.max_context_tokens <= 0 or self.hard_token_cap <= 0:
            raise ValueError("Token limits must be positive.")
        if self.hard_token_cap < self.max_context_tokens:
            self.max_context_tokens = self.hard_token_cap

    def can_fit(self, text: str) -> bool:
        return self.used_tokens + estimate_tokens(text) <= self.hard_token_cap

    def add_context(self, label: str, text: str) -> int:
        tokens = estimate_tokens(text)
        projected = self.used_tokens + tokens
        if projected > self.hard_token_cap:
            self.capped = True
            raise BudgetExceeded(
                f"Hard token cap exceeded by {label}: {projected}/{self.hard_token_cap}"
            )
        self.used_tokens = projected
        self.estimated_cost_usd += (tokens / 1000.0) * self.input_cost_per_1k
        warn_at = int(self.max_context_tokens * self.warn_ratio)
        if self.used_tokens >= warn_at:
            warning = (
                f"Token budget warning after {label}: "
                f"{self.used_tokens}/{self.max_context_tokens} estimated context tokens used"
            )
            if warning not in self.warnings:
                self.warnings.append(warning)
        if self.estimated_cost_usd >= self.budget_usd:
            warning = (
                f"Cost budget warning after {label}: "
                f"${self.estimated_cost_usd:.4f}/${self.budget_usd:.4f} estimated"
            )
            if warning not in self.warnings:
                self.warnings.append(warning)
        return tokens

    def add_model_usage(self, input_tokens: int, output_tokens: int) -> None:
        projected = self.used_tokens + input_tokens + output_tokens
        if projected > self.hard_token_cap:
            self.capped = True
            raise BudgetExceeded(
                f"Hard token cap exceeded by model usage: {projected}/{self.hard_token_cap}"
            )
        self.used_tokens = projected
        self.estimated_cost_usd += (input_tokens / 1000.0) * self.input_cost_per_1k
        self.estimated_cost_usd += (output_tokens / 1000.0) * self.output_cost_per_1k

    def snapshot(self) -> BudgetSnapshot:
        return BudgetSnapshot(
            max_context_tokens=self.max_context_tokens,
            hard_token_cap=self.hard_token_cap,
            used_tokens=self.used_tokens,
            estimated_cost_usd=self.estimated_cost_usd,
            warnings=list(self.warnings),
            capped=self.capped,
        )
