# RepoGuard Pitch

RepoGuard is a CLI-based AI security review agent for developers who build apps quickly and want to catch obvious vulnerabilities before running or shipping the project.

The target use case is a vibe-coded app: the app may work, but the developer has not yet checked whether it is safe. RepoGuard scans the repository, finds risky patterns, ranks findings by severity, explains the evidence, and produces a Markdown and JSON report with recommended improvements.

RepoGuard is built like a Claude Code/Codex-style developer agent, but it specializes in repository security review instead of general coding. A main orchestrator coordinates multiple scanner agents in parallel. Each sub-agent has a focused responsibility, such as unsafe upload detection, filesystem risk analysis, Python security scanning, dependency vulnerability checks, secret scanning, license review, or multi-language SAST.

The system uses context engineering to keep large tool outputs out of the main context. Scanner output is compressed, important lines are preserved, repeated noise is reduced, and possible secrets are redacted before the final report agent sees the data.

RepoGuard also tracks estimated token usage and cost while the scan is running. It can warn when the context budget is getting high and stop the scan if a hard cap would be exceeded.

Tool execution is guarded. RepoGuard only allows specific scanner binaries and `git clone`, blocks shell metacharacters, applies timeouts, limits output size, and runs commands inside an isolated workspace. It does not execute arbitrary project install scripts, tests, build scripts, or entrypoints from the scanned repository.

The project is packaged as a CLI and can be run locally or through Docker Compose. Configuration is controlled through environment variables and documented in `.env.example`.

The goal is not to replace Claude Code or Codex completely. The goal is to build a focused agentic security assistant that helps developers inspect a repository, understand the risks, and decide what should be fixed before trusting the code.
