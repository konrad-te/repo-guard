# RepoGuard Architecture

## Product Shape

RepoGuard is a CLI-first agentic security review tool.

The user gives RepoGuard a GitHub repository URL or local repository path. RepoGuard prepares an isolated workspace, starts multiple scanner agents concurrently, normalizes their results, manages context and budget, and writes an incremental security report.

## High-Level Flow

1. User runs `repoguard scan <repo>`.
2. CLI loads configuration from environment variables.
3. Workspace layer clones or resolves the target repository.
4. Main orchestrator creates the scan report and budget tracker.
5. Scanner agents run concurrently with a bounded semaphore.
6. Each scanner agent returns normalized findings.
7. Raw scanner output is compressed and redacted before entering report context.
8. Budget tracker records estimated context tokens and cost.
9. Partial Markdown and JSON reports are rewritten after each scanner completes.
10. Final report agent creates an executive summary and recommendations.
11. Orchestrator yields the final result to the user.

## Main Components

### CLI

File: `src/repoguard/cli.py`

Responsibilities:

- parse commands and flags
- load runtime configuration
- start the scan orchestrator
- print report paths, risk level, and budget warnings
- return meaningful exit codes

### Main Orchestrator

File: `src/repoguard/orchestrator/runner.py`

Responsibilities:

- coordinate the full scan lifecycle
- spawn scanner agents in parallel
- collect scanner results
- update risk level
- manage budget and context
- decide whether to continue scanning or stop because of a hard budget cap
- yield the final report back to the user

### Scanner Agents

Folder: `src/repoguard/scanners/`

Scanner agents are bounded sub-agents. Each agent has one responsibility and returns a shared `ScannerResult` schema.

Current scanner agents:

- `filesystem-agent`: checks repository inventory and risky filenames
- `upload-risk-agent`: checks upload handlers for missing file size, file count, and file type controls
- `license-agent`: checks for missing or restrictive top-level licenses
- `bandit`: Python security static analysis
- `semgrep`: multi-language static analysis
- `trufflehog`: secret scanning
- `pip-audit`: Python dependency vulnerability scanning

### Guarded Execution Layer

Files:

- `src/repoguard/execution/policy.py`
- `src/repoguard/execution/runner.py`

Responsibilities:

- allow only approved scanner binaries
- allow only safe `git clone` usage
- block shell metacharacters
- prevent working directory escape
- apply command timeouts
- limit stdout/stderr size
- avoid shell execution by using `asyncio.create_subprocess_exec`

### Context Engineering

File: `src/repoguard/orchestrator/context.py`

Responsibilities:

- redact likely secrets
- compress long scanner output
- keep important security lines
- preserve useful head/tail context
- reduce repeated noise
- compact JSON before adding it to report-agent context

### Token And Cost Budget

File: `src/repoguard/orchestrator/budget.py`

Responsibilities:

- estimate context token usage
- estimate cost
- warn near configured budget
- enforce a hard token cap
- expose budget snapshots in the report

### Report Agent

File: `src/repoguard/ai/report_agent.py`

Responsibilities:

- turn scanner-backed facts into summary and recommendations
- use Gemini enrichment when `GEMINI_API_KEY` is set
- fall back to deterministic local triage without an API key
- avoid unsupported claims by using only scanner-backed data

### Reporting

File: `src/repoguard/reporting/writer.py`

Responsibilities:

- write Markdown report
- write JSON report
- update reports incrementally while agents complete
- keep partial reports readable if a scan stops early

## Agent Decision Loop

RepoGuard is not a chatbot loop, but it has an agentic orchestration loop:

1. schedule scanner sub-agents
2. wait for the next completed agent
3. compact and budget-check the result
4. update report and risk level
5. continue if budget allows
6. stop early if the hard cap is reached
7. enrich final report
8. yield final result to the user

This satisfies the Assignment 2-style behavior at the product level: the system decides whether to continue tool use or stop and return results.

## Strengths

- parallel scanner-agent architecture
- scanner-backed evidence instead of vague AI guesses
- safe command execution
- output compression and secret redaction
- budget warnings and hard cap
- works without an API key through deterministic report generation
- Docker-based packaging

## Weaknesses

- scanner quality depends on available external tools
- local runs may skip scanners if binaries are missing
- token and cost accounting is estimated
- the current version focuses on review and reporting, not broad autonomous coding
- some vulnerability types require deeper framework-specific analysis
