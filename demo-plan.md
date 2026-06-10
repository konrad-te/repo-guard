# RepoGuard Demo Plan

## Demo Goal

Show that RepoGuard behaves like a focused Claude Code/Codex-style agent specialized in repository security review.

The demo should prove:

- the tool can scan a repo
- multiple scanner agents run
- findings are normalized into a report
- context is compressed/redacted
- token/cost budget is tracked
- unsafe command execution is restricted
- reports are generated
- the result is understandable to a developer

## Preparation

1. Clone or open the RepoGuard project.
2. Copy `.env.example` to `.env`.
3. Set `REPO_URL` to a test repository or local vulnerable demo project.
4. Optionally leave `GEMINI_API_KEY` empty to show deterministic fallback.
5. Make sure Docker is available if using the Docker path.

## Demo Option A: Docker

```bash
cp .env.example .env
docker compose up --build
```

Expected result:

- Docker builds RepoGuard.
- RepoGuard starts a scan.
- Reports are written to `reports/<repo>/<timestamp>/`.

## Demo Option B: Local CLI

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
repoguard scan <repo-url-or-local-path> --no-ai
```

On macOS/Linux, activate the environment with:

```bash
source .venv/bin/activate
```

## Demo Script

1. Introduce the product:

   "RepoGuard is a CLI security review agent for vibe-coded apps. It scans a repo before the developer trusts, runs, or ships it."

2. Run a scan:

   ```bash
   repoguard scan examples/vulnerable-upload-app --no-ai
   ```

3. Point out concurrent scanner agents:

   - filesystem-agent
   - upload-risk-agent
   - license-agent
   - bandit
   - semgrep
   - trufflehog
   - pip-audit

   During the scan, the CLI prints live progress messages as scanner agents start, finish, and merge results into the report.

4. Open the generated Markdown report.

5. Show:

   - risk level
   - findings
   - evidence
   - recommendations
   - scanner status
   - budget section

6. Explain context engineering:

   - long scanner outputs are compressed
   - possible secrets are redacted
   - compacted output is what the final report agent sees

7. Explain tool safety:

   - no arbitrary shell
   - only allowlisted scanner binaries
   - shell metacharacters blocked
   - command timeouts and output limits
   - no project install/build/entrypoint scripts are run

8. Explain budget controls:

   - estimated tokens are counted
   - warnings are created near the soft budget
   - hard cap stops further context use
   - live progress output shows token and cost state while the scan runs

9. Demonstrate partial file editing:

   ```bash
   repoguard patch ./demo-vulnerable-app app/upload.py \
     --find "MAX_FILES = None" \
     --replace "MAX_FILES = 10"
   ```

   Explain that RepoGuard previews the targeted edit first. Then apply it with `--yes` if the preview is correct.

10. End with the final result:

   "The agent yields a report the developer can use before deploying or trusting the app."

## Suggested Vulnerable Demo Case

Use a small app with one or more obvious issues:

- upload route with no max file size
- upload route with no file count limit
- upload route with no MIME/type allowlist
- hardcoded fake API key
- vulnerable dependency in `requirements.txt`
- missing license file

The best demo finding for the product story is:

> A file upload endpoint allows unbounded uploads, which can fill storage or overload the database.

## Backup Demo

If external scanner binaries are missing locally, run with Docker or show that missing scanners are recorded as `skipped` instead of crashing the product.

This still demonstrates orchestration, reporting, safe failure behavior, and deterministic fallback.
