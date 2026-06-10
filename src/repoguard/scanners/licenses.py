from __future__ import annotations

from pathlib import Path

from repoguard.execution.runner import GuardedCommandRunner
from repoguard.models import AgentStatus, Finding, ScannerResult, Severity
from repoguard.scanners.base import ScannerAgent


RISKY_LICENSE_HINTS = {
    "agpl": Severity.HIGH,
    "gpl": Severity.MEDIUM,
    "lgpl": Severity.LOW,
}


class LicenseScanner(ScannerAgent):
    name = "license-agent"
    description = "Static license and dependency metadata inspection."

    async def scan(self, repo_path: Path, runner: GuardedCommandRunner) -> ScannerResult:
        result = ScannerResult(name=self.name, status=AgentStatus.COMPLETE)
        license_files = [
            path for path in repo_path.iterdir() if path.is_file() and path.name.lower().startswith("license")
        ]
        manifests = [
            "package.json",
            "pyproject.toml",
            "requirements.txt",
            "Cargo.toml",
            "go.mod",
            "pom.xml",
        ]
        present_manifests = [name for name in manifests if (repo_path / name).exists()]
        if not license_files:
            result.findings.append(
                Finding(
                    scanner=self.name,
                    title="Repository has no top-level license file",
                    severity=Severity.LOW,
                    description="No LICENSE file was found at the repository root.",
                    recommendation="Confirm license terms before running, copying, or redistributing this code.",
                )
            )
        for path in license_files:
            text = path.read_text(encoding="utf-8", errors="replace")[:20_000].lower()
            for hint, severity in RISKY_LICENSE_HINTS.items():
                if hint in text:
                    result.findings.append(
                        Finding(
                            scanner=self.name,
                            title=f"License may contain {hint.upper()} obligations",
                            severity=severity,
                            file=str(path),
                            description=f"The license text includes '{hint}', which may impose redistribution obligations.",
                            recommendation="Ask legal/maintainer review before embedding this code in a proprietary project.",
                        )
                    )
                    break
        result.summary = (
            f"Found {len(license_files)} top-level license file(s) and "
            f"{len(present_manifests)} dependency manifest(s): {', '.join(present_manifests) or 'none'}."
        )
        return result.finish()
