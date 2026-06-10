from __future__ import annotations

import asyncio
import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from repoguard.config import RepoGuardConfig
from repoguard.editing.patcher import apply_exact_replacement
from repoguard.orchestrator.runner import ScanOrchestrator


WEB_ROOT = Path(__file__).parent / "web"


class RepoGuardGuiServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], report_dir: Path, config_path: Path | None = None):
        super().__init__(server_address, RepoGuardGuiHandler)
        self.report_dir = report_dir
        self.config_path = config_path


class RepoGuardGuiHandler(BaseHTTPRequestHandler):
    server: RepoGuardGuiServer

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            self._json({"ok": True})
            return
        if parsed.path == "/api/reports":
            self._json({"reports": self._list_reports()})
            return
        if parsed.path == "/api/report":
            self._get_report(parsed.query)
            return
        self._static(parsed.path)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/scan":
            self._scan()
            return
        if parsed.path == "/api/patch":
            self._patch()
            return
        self._json({"error": "Unknown endpoint"}, status=404)

    def log_message(self, format: str, *args) -> None:
        return

    def _static(self, path: str) -> None:
        relative = "index.html" if path in {"/", ""} else path.lstrip("/")
        target = (WEB_ROOT / relative).resolve()
        root = WEB_ROOT.resolve()
        if target != root and root not in target.parents:
            self._json({"error": "Path escapes web root"}, status=403)
            return
        if not target.exists() or not target.is_file():
            self._json({"error": "Not found"}, status=404)
            return
        body = target.read_bytes()
        content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _scan(self) -> None:
        payload = self._read_json()
        repo = str(payload.get("repo", "")).strip()
        if not repo:
            self._json({"error": "repo is required"}, status=400)
            return
        events: list[str] = []
        try:
            config = RepoGuardConfig.from_env(self.server.config_path)
            config.report_dir = self.server.report_dir
            config.ai_enabled = not bool(payload.get("no_ai", True))
            if payload.get("fail_on"):
                config.fail_on_severity = str(payload["fail_on"]).lower()
            if payload.get("max_concurrency"):
                config.max_concurrency = int(payload["max_concurrency"])
            orchestrator = ScanOrchestrator(config, progress=events.append)
            report, markdown_path, json_path = asyncio.run(orchestrator.scan(repo))
            self._json(
                {
                    "report": report.to_dict(),
                    "markdown_path": str(markdown_path),
                    "json_path": str(json_path),
                    "events": events,
                }
            )
        except Exception as exc:
            self._json({"error": f"{type(exc).__name__}: {exc}", "events": events}, status=500)

    def _patch(self) -> None:
        payload = self._read_json()
        try:
            result = apply_exact_replacement(
                Path(str(payload.get("repo", ""))),
                str(payload.get("file", "")),
                str(payload.get("find", "")),
                str(payload.get("replace", "")),
                write=bool(payload.get("write", False)),
            )
            self._json(
                {
                    "changed": result.changed,
                    "message": result.message,
                    "file": str(result.file),
                    "preview": result.preview,
                }
            )
        except Exception as exc:
            self._json({"error": f"{type(exc).__name__}: {exc}"}, status=400)

    def _get_report(self, query: str) -> None:
        values = parse_qs(query)
        relative = values.get("path", [""])[0]
        try:
            target = self._safe_report_path(relative)
            data = json.loads(target.read_text(encoding="utf-8"))
            markdown = target.with_name("report.md")
            self._json(
                {
                    "report": data,
                    "json_path": str(target),
                    "markdown": markdown.read_text(encoding="utf-8") if markdown.exists() else "",
                }
            )
        except Exception as exc:
            self._json({"error": f"{type(exc).__name__}: {exc}"}, status=400)

    def _list_reports(self) -> list[dict]:
        reports: list[dict] = []
        root = self.server.report_dir
        if not root.exists():
            return reports
        for path in root.rglob("findings.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            rel = path.relative_to(root).as_posix()
            reports.append(
                {
                    "path": rel,
                    "repo": data.get("repo", "unknown"),
                    "risk_level": data.get("risk_level", "info"),
                    "status": data.get("status", "unknown"),
                    "summary": data.get("summary", ""),
                    "started_at": data.get("started_at"),
                    "finished_at": data.get("finished_at"),
                    "findings_count": len(data.get("findings", [])),
                }
            )
        reports.sort(key=lambda item: item.get("finished_at") or item.get("started_at") or "", reverse=True)
        return reports

    def _safe_report_path(self, relative: str) -> Path:
        root = self.server.report_dir.resolve()
        target = (root / relative).resolve()
        if target != root and root not in target.parents:
            raise PermissionError("Report path escapes report directory.")
        if target.name != "findings.json" or not target.exists():
            raise FileNotFoundError("Report JSON not found.")
        return target

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8") or "{}")

    def _json(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_gui(host: str, port: int, report_dir: Path, config_path: Path | None = None) -> None:
    server = RepoGuardGuiServer((host, port), report_dir=report_dir, config_path=config_path)
    print(f"RepoGuard GUI running at http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    server.serve_forever()
