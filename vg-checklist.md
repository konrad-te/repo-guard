# VG Checklist For RepoGuard

## 1. Product Pitch

Status: fulfilled.

Evidence:

- `pitch.md`
- `README.md`

RepoGuard is described as a real product: a CLI security review agent for developers who want to inspect vibe-coded apps before running or shipping them.

## 2. Claude Code/Codex-Like Agent

Status: fulfilled.

RepoGuard is a developer CLI agent that inspects repositories, uses tools, coordinates sub-agents, manages context, and returns a final report.

It specializes in security review instead of being a general coding assistant.

## 3. Multi-Agent System

Status: fulfilled.

Evidence:

- `src/repoguard/orchestrator/runner.py`
- `src/repoguard/scanners/`
- `tests/test_orchestrator.py`

The main orchestrator starts scanner agents concurrently and merges their results into the main report.

## 4. Context Engineering

Status: fulfilled.

Evidence:

- `src/repoguard/orchestrator/context.py`
- `src/repoguard/orchestrator/runner.py`

RepoGuard compresses long scanner outputs, preserves important security lines, removes repeated noise, redacts likely secrets, and compacts JSON before adding scanner-backed facts to the report-agent context.

## 5. Token And Cost Monitoring

Status: fulfilled.

Evidence:

- `src/repoguard/orchestrator/budget.py`
- generated report budget section

RepoGuard estimates token usage and cost, creates warnings near configured limits, and enforces a hard context cap.

## 6. Protection Against Harmful Tool Calls

Status: fulfilled.

Evidence:

- `src/repoguard/execution/policy.py`
- `src/repoguard/execution/runner.py`
- `tests/test_policy.py`

RepoGuard allowlists scanner binaries, blocks shell metacharacters, restricts `git` usage, prevents workspace escape, applies timeouts, and limits output size.

## 7. Bash Command Execution

Status: mostly fulfilled.

RepoGuard executes external command-line scanner tools through a guarded subprocess runner. It does not expose arbitrary bash to the user.

This is safer for the product because RepoGuard should scan untrusted repositories without running their scripts.

This is the most arguable requirement because RepoGuard intentionally allows only safe scanner commands instead of arbitrary user-provided shell.

## 8. Partial File Editing

Status: fulfilled.

Evidence:

- `src/repoguard/editing/patcher.py`
- `tests/test_patcher.py`

RepoGuard includes a guarded `repoguard patch` command for exact partial replacements. It is dry-run by default, requires `--yes` to write, refuses ambiguous replacements, and prevents path escape outside the selected repository.

## 9. Deployable / Packaged Solution

Status: fulfilled.

Evidence:

- `Dockerfile`
- `docker-compose.yml`
- `pyproject.toml`
- `README.md`

RepoGuard can be run through Docker Compose or installed locally as a Python CLI.

## 10. Config And Secrets

Status: fulfilled.

Evidence:

- `.env.example`
- `repoguard.example.toml`
- `src/repoguard/config.py`

Non-secret runtime settings can be loaded from a TOML config file. Secrets are loaded from environment variables. Environment variables can override config-file values.

## 11. Assignment 2 Baseline Behavior

Status: fulfilled.

RepoGuard decides whether to continue scanning or stop based on scanner completion, errors, and budget caps. It yields a final report when the scan is complete or when the hard budget cap stops the run.

The CLI prints live progress as scanner agents start, finish, and merge results. This makes the decision loop visible during the demo.

## 12. Presentation / Demo

Status: planned.

Evidence:

- `demo-plan.md`

The demo should show a scan, generated report, scanner agents, context engineering, budget warnings, and safety policy.

## 13. Architecture Understanding

Status: fulfilled through documentation.

Evidence:

- `architecture.md`
- `README.md`

The architecture is explainable at a high level without reading every line of Python code.

## Remaining Priority Work

1. Prepare final screenshots and a short demo recording/script.
2. Optionally add more auto-fix templates beyond upload-handler fixes.
