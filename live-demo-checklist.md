# RepoGuard Live Demo Checklist

## Before The Demo

- Make sure you are inside the `RepoGuard` folder.
- Make sure the local package is installed or use `python -m repoguard`.
- Leave `GEMINI_API_KEY` empty if you want to show deterministic fallback.
- Use `--no-ai` for the safest live demo path.

## Command 1: Run Security Scan

```bash
python -m repoguard scan examples/vulnerable-upload-app --no-ai --fail-on critical
```

Expected result:

- scanner agents start and finish
- `upload-risk-agent` finds findings
- terminal shows token/cost progress
- final risk is `HIGH`
- report path is printed

## Command 2: Open The Report

Open the printed `report.md`.

Show:

- risk level
- upload finding
- evidence line
- recommendation
- budget section
- scanner-agent statuses

Key finding to point at:

```text
Upload handler has no obvious resource limit
```

Key evidence:

```text
files = request.files.getlist("files")
```

## Command 3: Show Partial File Editing

```bash
python -m repoguard patch examples/vulnerable-upload-app app.py --find "for file in files:" --replace "for file in files[:10]:"
```

Expected result:

- dry-run message
- partial edit preview
- one line removed
- one line added
- file is not changed yet

## Optional Command 4: Apply Patch

Only run this if you want to actually modify the demo app:

```bash
python -m repoguard patch examples/vulnerable-upload-app app.py --find "for file in files:" --replace "for file in files[:10]:" --yes
```

Then rerun the scan to show the file-count part is improved.

## Things To Say During Demo

- "The main orchestrator starts parallel scanner agents."
- "The upload-risk-agent is specialized for the exact issue I wanted to catch."
- "Tool outputs are compressed and redacted before entering report context."
- "The command runner is guarded and does not run arbitrary project scripts."
- "Budget and token usage are tracked during the scan."
- "The patch command demonstrates partial file editing with dry-run by default."

## If Something Goes Wrong

If external scanners are skipped:

- say this is expected locally when scanner binaries are missing
- point out that the custom `upload-risk-agent` still runs
- mention Docker installs the external scanner tools

If Gemini is not configured:

- say RepoGuard has deterministic fallback
- use `--no-ai`

