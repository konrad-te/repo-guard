# RepoGuard

RepoGuard is an agentic CLI that scans a GitHub repository before you run someone else's code. It clones the repo into an isolated workspace, starts parallel scanner agents, runs real security tools, compresses long outputs before they enter AI context, tracks token/cost budgets, and writes an incremental Markdown plus JSON report.

## What It Checks

- `filesystem-agent`: risky filenames, language/file inventory
- `upload-risk-agent`: unsafe file upload handlers, missing upload limits/type checks
- `license-agent`: missing or potentially restrictive top-level licenses
- `bandit`: Python static security analysis
- `semgrep`: multi-language SAST
- `trufflehog`: secret scanning
- `pip-audit`: Python dependency vulnerabilities from `requirements*.txt`

The scanner agents use guarded subprocess execution. RepoGuard does not run project install scripts, build scripts, tests, entrypoints, or arbitrary shell supplied by the repository.

## Quick Start With Docker

```bash
cp .env.example .env
docker compose build
```

Run the built-in vulnerable upload demo from Docker:

```bash
docker compose run --rm repoguard
```

To scan a specific repository instead:

```bash
docker compose run --rm repoguard scan https://github.com/org/repo --no-ai
```

To run the GUI from Docker:

```bash
docker compose up -d gui
```

Then open:

```text
http://127.0.0.1:8765
```

On Windows, Docker cannot automatically see arbitrary `C:\...` folders. To scan local projects from the Docker GUI, set these values in `.env` and restart the GUI container:

```text
REPOGUARD_HOST_PROJECTS=C:\Users\your-name\Desktop\Projects
REPOGUARD_HOST_PATH_PREFIX=C:\Users\your-name\Desktop\Projects
REPOGUARD_CONTAINER_PATH_PREFIX=/host-projects
```

After that, you can enter a normal Windows path in the GUI, such as:

```text
C:\Users\your-name\Desktop\Projects\Some App
```

RepoGuard maps that path to the mounted Docker folder before scanning.

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

To run the built-in vulnerable upload demo:

```bash
repoguard scan examples/vulnerable-upload-app --no-ai
```

To open the local GUI:

```bash
repoguard gui
```

Then visit:

```text
http://127.0.0.1:8765
```

The GUI includes a scan page and a reports history page:

```text
http://127.0.0.1:8765/reports.html
```

## Agentic Architecture

RepoGuard separates agency from execution:

- The orchestrator schedules independent scanner agents concurrently.
- Each scanner agent has one bounded responsibility and normalizes findings into a shared schema.
- The guarded command runner only allows scanner binaries and safe Git commands, blocks shell metacharacters, runs commands without a shell, bounds output, and applies timeouts.
- Raw scanner output is compressed and redacted before it can be used by the report agent.
- The token budget monitor warns near the configured budget and raises a hard cap before oversized context is added.
- The report writer atomically rewrites stable report sections after each scanner completes, so partial reports remain readable.

If `GEMINI_API_KEY` is set, the final report agent asks Gemini to enrich the executive summary and recommendations using only scanner-backed facts. Without an API key, RepoGuard uses a deterministic local triage agent.

## CLI

```bash
repoguard scan <github-url-or-local-path> \
  --config repoguard.toml \
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

RepoGuard also includes a guarded partial-edit command for targeted fixes:

```bash
repoguard patch examples/vulnerable-upload-app app.py \
  --find "for file in files:" \
  --replace "for file in files[:10]:"
```

The command is dry-run by default and prints a preview. Add `--yes` to write the change:

```bash
repoguard patch examples/vulnerable-upload-app app.py \
  --find "for file in files:" \
  --replace "for file in files[:10]:" \
  --yes
```

Partial edits are restricted to files inside the selected repository path and ambiguous replacements are refused.

## Guarded Auto-Fixes

The GUI can preview and apply safe guided edits for supported findings. The guarded editor panel shows the target file, safety steps, and unified diff before anything is written.

Current supported edit types:

- Flask and FastAPI upload handlers that read uploaded files without count, size, or file-type checks
- vulnerable Python dependencies in `requirements*.txt` when `pip-audit` reports a fixed version
- missing top-level license findings, handled by creating `LICENSE_REVIEW.md` as a review reminder instead of inventing legal terms

Auto-fixes are intentionally guarded:

- they only work on local repository paths, not temporary GitHub URL scans
- they show a preview before writing
- they require explicit user approval
- they refuse unknown patterns instead of guessing

For a GitHub repository URL, RepoGuard can scan and report findings, but it cannot write fixes back to the remote repository. Clone it locally first, scan the local folder in the GUI, then use the finding's **Preview fix** and **Apply fix** buttons.

Example:

```bash
git clone https://github.com/org/repo
repoguard gui
```

Then scan the local folder path instead of the GitHub URL.

## Configuration

Non-secret settings can be kept in a TOML config file:

```bash
repoguard scan <repo> --config repoguard.example.toml
```

Environment variables still override config-file values. Secrets such as `GEMINI_API_KEY` should stay in `.env` or the shell environment, not in the TOML file.

The default example config uses Gemini free-tier cost values of `0` for input and output tokens. If you move to a paid tier, update `INPUT_COST_PER_1K` and `OUTPUT_COST_PER_1K` or the matching TOML values.
