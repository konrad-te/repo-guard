# RepoGuard Presentation Script

## 1. Short Introduction

RepoGuard is a CLI-based AI security review agent for developers who build apps quickly and want to check them before running or shipping them.

It also includes a clean local GUI for demos and review workflows. The CLI is still the core product, while the GUI makes scan results, reports, and patch previews easier to inspect.

The idea is based on a common problem with vibe-coded projects: the app may work, but it may still contain obvious security mistakes, such as unsafe file uploads, exposed secrets, vulnerable dependencies, missing validation, or risky repository contents.

RepoGuard is in the same category as Claude Code or Codex because it is an agentic developer tool that works inside a codebase, uses tools, coordinates sub-agents, manages context, and returns a useful result to the developer. But instead of being a general coding assistant, it specializes in security review.

## 2. Product Pitch

The product pitch is:

> RepoGuard scans a repository before the developer trusts, runs, or deploys it. It starts parallel security agents, collects evidence-backed findings, manages token and cost budgets, and produces a clear report with risks and suggested improvements.

For example, if I vibe-coded an app with a file upload endpoint and forgot to limit how many files a user can upload, RepoGuard can flag that as a denial-of-service or storage exhaustion risk.

## 3. Architecture Explanation

RepoGuard has a main orchestrator and several scanner agents.

The main orchestrator is responsible for:

- preparing the workspace
- starting scanner agents in parallel
- collecting their results
- compressing large tool outputs
- tracking token and cost budget
- writing the report
- deciding when the scan is complete and yielding back to the user

The scanner agents are specialized sub-agents. Current examples are:

- `filesystem-agent`, which checks repository structure and risky file names
- `upload-risk-agent`, which checks upload handlers for missing limits
- `license-agent`, which checks for missing license information
- `bandit`, for Python security scanning
- `semgrep`, for multi-language static analysis
- `trufflehog`, for secret scanning
- `pip-audit`, for vulnerable Python dependencies

Each agent has a bounded responsibility and returns normalized findings into the same report format.

## 4. Context Engineering

RepoGuard has context engineering because scanner output can be very large.

Instead of sending raw outputs directly into the report agent, RepoGuard:

- compresses long output
- keeps important security lines
- removes repeated noise
- redacts possible secrets
- compacts JSON results before they enter report context

This prevents the context window from being wasted on huge raw tool outputs.

## 5. Token And Cost Control

RepoGuard tracks estimated token usage and estimated cost during the scan.

It supports:

- soft budget warnings
- hard token cap
- budget information in the report
- live progress messages during the scan

The current setup uses Gemini free-tier cost defaults, so the default estimated token cost is zero unless paid-tier values are configured.

## 6. Tool Safety

RepoGuard is designed to inspect untrusted repositories safely.

It does not run arbitrary shell commands from the project.

The guarded execution layer:

- only allows approved scanner binaries
- only allows safe `git clone`
- blocks shell metacharacters
- prevents workspace escape
- applies timeouts
- limits command output size

This is important because scanning a random repository should not mean trusting its scripts.

## 7. Partial File Editing

RepoGuard also supports partial file editing through a guarded patch command.

It does exact search/replace inside a local repository path.

It is dry-run by default, so it previews the change first. The user must add `--yes` to actually write the edit.

This satisfies the partial file editing requirement without rewriting whole files.

## 8. Demo Commands

Start the GUI:

```bash
repoguard gui
```

Then open:

```text
http://127.0.0.1:8765
```

Run the vulnerable demo scan:

```bash
repoguard scan examples/vulnerable-upload-app --no-ai --fail-on critical
```

What to point out:

- scanner agents start and finish
- `upload-risk-agent` finds upload issues
- budget/token progress appears in the terminal
- report path is printed
- risk level is HIGH

Open the generated report and show:

- `Upload handler has no obvious resource limit`
- evidence line: `files = request.files.getlist("files")`
- recommendation to add file size and count limits
- budget section
- scanner agent statuses

Then show partial editing:

```bash
repoguard patch examples/vulnerable-upload-app app.py \
  --find "for file in files:" \
  --replace "for file in files[:10]:"
```

Explain:

- this is a dry run
- RepoGuard previews a targeted edit
- it edits only one section of the file
- `--yes` would apply it

## 9. Docker And Configuration

RepoGuard is packaged with:

- `Dockerfile`
- `docker-compose.yml`
- `pyproject.toml`
- `.env.example`
- `repoguard.example.toml`

Secrets such as `GEMINI_API_KEY` go in `.env` or environment variables.

Non-secret settings such as budget, model name, scanner timeout, report directory, and concurrency can live in the TOML config file.

## 10. Strengths

RepoGuard's strengths are:

- focused product idea
- parallel scanner-agent architecture
- real security tool integration
- custom upload-risk scanner for the main demo case
- safe command execution
- context compression and secret redaction
- token/cost monitoring
- Docker packaging
- deterministic fallback when no Gemini key is provided

## 11. Weaknesses

RepoGuard also has limitations:

- some scanners may be skipped locally if their binaries are not installed
- the upload scanner is heuristic, so it can miss framework-specific patterns
- token and cost tracking is estimated
- partial fixes are simple exact replacements, not full autonomous repair
- deeper security review still requires human judgment

## 12. Closing

The goal of RepoGuard is not to fully replace Claude Code or Codex.

The goal is to build a focused Claude Code-style agent that helps developers make quickly built apps safer before trusting or deploying them.
