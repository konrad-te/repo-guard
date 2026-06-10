from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AgentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMED_OUT = "timed_out"
    BLOCKED = "blocked"


SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(slots=True)
class Finding:
    scanner: str
    title: str
    severity: Severity
    file: str | None = None
    line: int | None = None
    description: str = ""
    recommendation: str = ""
    evidence: str = ""
    rule_id: str | None = None
    confidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "title": self.title,
            "severity": self.severity.value,
            "file": self.file,
            "line": self.line,
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "rule_id": self.rule_id,
            "confidence": self.confidence,
        }


@dataclass(slots=True)
class CommandResult:
    command: list[str]
    cwd: str
    exit_code: int | None
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    timed_out: bool = False
    blocked_reason: str | None = None
    output_truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "cwd": self.cwd,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_seconds": round(self.duration_seconds, 3),
            "timed_out": self.timed_out,
            "blocked_reason": self.blocked_reason,
            "output_truncated": self.output_truncated,
        }


@dataclass(slots=True)
class ScannerResult:
    name: str
    status: AgentStatus
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    command: CommandResult | None = None
    compressed_output: str = ""
    error: str | None = None
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: str | None = None
    duration_seconds: float = 0.0

    def finish(self, status: AgentStatus | None = None) -> "ScannerResult":
        self.finished_at = datetime.now(timezone.utc).isoformat()
        if status is not None:
            self.status = status
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "findings": [finding.to_dict() for finding in self.findings],
            "summary": self.summary,
            "command": self.command.to_dict() if self.command else None,
            "compressed_output": self.compressed_output,
            "error": self.error,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.duration_seconds, 3),
        }


@dataclass(slots=True)
class BudgetSnapshot:
    max_context_tokens: int
    hard_token_cap: int
    used_tokens: int
    estimated_cost_usd: float
    warnings: list[str] = field(default_factory=list)
    capped: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_context_tokens": self.max_context_tokens,
            "hard_token_cap": self.hard_token_cap,
            "used_tokens": self.used_tokens,
            "estimated_cost_usd": round(self.estimated_cost_usd, 6),
            "warnings": self.warnings,
            "capped": self.capped,
        }


@dataclass(slots=True)
class ScanReport:
    repo: str
    repo_path: str
    started_at: str
    finished_at: str | None = None
    status: str = "running"
    risk_level: Severity = Severity.INFO
    summary: str = ""
    recommendations: list[str] = field(default_factory=list)
    scanner_results: list[ScannerResult] = field(default_factory=list)
    budget: BudgetSnapshot | None = None

    def all_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        for result in self.scanner_results:
            findings.extend(result.findings)
        return findings

    def recalculate_risk(self) -> None:
        findings = self.all_findings()
        if not findings:
            self.risk_level = Severity.INFO
            return
        self.risk_level = max(findings, key=lambda item: SEVERITY_ORDER[item.severity]).severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo": self.repo,
            "repo_path": self.repo_path,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "status": self.status,
            "risk_level": self.risk_level.value,
            "summary": self.summary,
            "recommendations": self.recommendations,
            "budget": self.budget.to_dict() if self.budget else None,
            "scanner_results": [result.to_dict() for result in self.scanner_results],
            "findings": [finding.to_dict() for finding in self.all_findings()],
        }
