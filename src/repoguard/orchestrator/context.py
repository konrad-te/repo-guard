from __future__ import annotations

import json
import re
from collections import Counter


SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret|password)(['\"\s:=]+)([A-Za-z0-9_\-/.+=]{8,})"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
]


def redact_secrets(text: str) -> str:
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(lambda match: match.group(0)[:12] + "[REDACTED]", redacted)
    return redacted


def compress_output(text: str, max_chars: int = 12_000) -> str:
    text = redact_secrets(text or "")
    if len(text) <= max_chars:
        return text

    lines = text.splitlines()
    keyword_lines: list[str] = []
    repeated_lines: list[str] = []
    repeated = Counter(lines)
    seen: set[str] = set()
    keywords = (
        "error",
        "warning",
        "critical",
        "high",
        "medium",
        "low",
        "secret",
        "vulnerab",
        "cve-",
        ".py:",
        ".js:",
        ".ts:",
        ".go:",
        ".java:",
    )
    for line in lines:
        lower = line.lower()
        if any(keyword in lower for keyword in keywords):
            keyword_lines.append(line)
        elif repeated[line] > 3 and line not in seen:
            repeated_lines.append(f"{line}  [repeated {repeated[line]} times]")
            seen.add(line)
    important: list[str] = []
    for line in keyword_lines + repeated_lines:
        important.append(line)
        if sum(len(item) + 1 for item in important) > max_chars // 3:
            break

    head = "\n".join(lines[:40])
    tail = "\n".join(lines[-40:])
    body = "\n".join(important)
    compressed = (
        "[RepoGuard compressed scanner output]\n"
        f"Original characters: {len(text)}\n"
        f"Original lines: {len(lines)}\n\n"
        "[Important lines]\n"
        f"{body}\n\n"
        "[Head]\n"
        f"{head}\n\n"
        "[Tail]\n"
        f"{tail}"
    )
    if len(compressed) > max_chars:
        reserved = (
            "[RepoGuard compressed scanner output]\n"
            f"Original characters: {len(text)}\n"
            f"Original lines: {len(lines)}\n\n"
            "[Important lines]\n"
            f"{body}\n\n"
            "[Head/Tail omitted to fit compression budget]"
        )
        if len(reserved) <= max_chars:
            compressed = reserved
        else:
            keep = max_chars - 40
            compressed = reserved[:keep] + "\n[...truncated...]"
    return compressed


def compact_json(data: object, max_chars: int = 12_000) -> str:
    try:
        rendered = json.dumps(data, ensure_ascii=False, sort_keys=True)
    except TypeError:
        rendered = str(data)
    return compress_output(rendered, max_chars=max_chars)
