from __future__ import annotations

from repoguard.scanners.bandit import BanditScanner
from repoguard.scanners.filesystem import FilesystemScanner
from repoguard.scanners.licenses import LicenseScanner
from repoguard.scanners.pip_audit import PipAuditScanner
from repoguard.scanners.semgrep import SemgrepScanner
from repoguard.scanners.trufflehog import TruffleHogScanner


def default_scanners():
    return [
        FilesystemScanner(),
        LicenseScanner(),
        BanditScanner(),
        SemgrepScanner(),
        TruffleHogScanner(),
        PipAuditScanner(),
    ]
