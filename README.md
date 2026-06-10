# RepoGuard

RepoGuard is an agentic CLI that scans a GitHub repository before you run someone else's code. It clones the repo into an isolated workspace, starts parallel scanner agents, runs real security tools, compresses long outputs before they enter AI context, tracks token/cost budgets, and writes an incremental Markdown plus JSON report.

## What It Checks

- `filesystem-agent`: risky filenames, language/file inventory
- `license-agent`: missing or potentially restrictive top-level licenses
- `bandit`: Python static security analysis
- `semgrep`: multi-language SAST
- `trufflehog`: secret scanning
- `pip-audit`: Python dependency vulnerabilities from `requirements*.txt`

The scanner agents use guarded subprocess execution. RepoGuard does not run project install scripts, build scripts, tests, entrypoints, or arbitrary shell supplied by the repository.

## Quick Start With Docker

```bash
cp .env.example .env
# edit REPO_URL in .env
docker compose up --build
```

Reports are written to:

```text
reports/<repo>/<timestamp>/report.md
reports/<repo>/<timestamp>/findings.json
```

## Local Development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
repoguard scan https://github.com/org/repo --no-ai
```

External scanner binaries are optional for local development. Missing tools are recorded as `skipped` in the report. The Docker image installs the scanner CLIs.

## Agentic Architecture

RepoGuard separates agency from execution:

- The orchestrator schedules independent scanner agents concurrently.
- Each scanner agent has one bounded responsibility and normalizes findings into a shared schema.
- The guarded command runner only allows scanner binaries and `git clone`, blocks shell metacharacters, uses `create_subprocess_exec`, bounds output, and applies timeouts.
- Raw scanner output is compressed and redacted before it can be used by the report agent.
- The token budget monitor warns near the configured budget and raises a hard cap before oversized context is added.
- The report writer atomically rewrites stable report sections after each scanner completes, so partial reports remain readable.

If `OPENAI_API_KEY` is set, the final report agent asks an OpenAI model to enrich the executive summary and recommendations using only scanner-backed facts. Without an API key, RepoGuard uses a deterministic local triage agent.

## CLI

```bash
repoguard scan <github-url-or-local-path> \
  --output reports \
  --concurrency 5 \
  --timeout 300 \
  --max-tokens 120000 \
  --hard-token-cap 150000 \
  --budget-usd 1.50 \
  --fail-on high
```

Exit codes:

- `0`: scan completed below the fail threshold
- `1`: risk is at or above `--fail-on`
- `2`: fatal setup/runtime error
- `130`: interrupted
