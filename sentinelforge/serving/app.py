# -*- coding: utf-8 -*-
"""Standard-library HTTP API (no external server dependency).

Endpoints:
- GET  /health          -> {"ok": true, "sovereignty": {...}}
- GET  /v1/info         -> engine info (mode, skill, budget)
- GET  /v1/modes        -> reasoning-mode table
- POST /v1/scan         -> {"text": "...", "path": "..."} -> full scan result
- GET  /v1/bench        -> benchmark table
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

from ..core.engine import Engine
from .. import bench as benchmod


def make_handler(cfg):
    engine = Engine(cfg)

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, obj):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/health":
                self._send(200, {"ok": True, "sovereignty": engine.sovereignty.audit()})
            elif self.path == "/v1/info":
                self._send(200, {"name": "sentinelforge", "version": "0.1.0",
                                 "mode": engine.modes.label(),
                                 "skill": cfg["model"]["skill"],
                                 "token_budget": cfg["engine"]["token_budget"]})
            elif self.path == "/v1/modes":
                from ..core.modes import MODES
                self._send(200, {"modes": MODES})
            elif self.path == "/v1/bench":
                rows = benchmod.run_all()
                self._send(200, {"rows": rows, "summary": benchmod.summarize(rows)})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            if self.path == "/v1/scan":
                ln = int(self.headers.get("Content-Length", 0))
                data = json.loads(self.rfile.read(ln).decode("utf-8"))
                text = data.get("text", "")
                path = data.get("path", "inline")
                r = engine.scan(path, text)
                self._send(200, r)
            else:
                self._send(404, {"error": "not found"})

        def log_message(self, *args):
            pass

    return Handler


def serve(host="127.0.0.1", port=8420, cfg=None):
    if cfg is None:
        from ..config import load_config
        cfg = load_config()
    handler = make_handler(cfg)
    srv = HTTPServer((host, port), handler)
    print("[serve] sentinelforge listening on http://%s:%d" % (host, port))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
