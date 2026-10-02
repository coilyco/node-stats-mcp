"""Exporter health endpoint: how long ago the filesystem snapshot last collected.

Gatus probes it (teable:coilyco/deploy#8704), replacing the SigNoz rules that
fired on the exporter's own metrics going quiet. Off unless
`NODE_STATS_HEALTH_PORT` is set. Contract in docs/exporter-health.md.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HEALTH_PATH = "/healthz"
# Reported before any cycle collected, so the field is never absent or null.
# A probe gating on `< 900` fails closed instead of passing on a missing value.
NEVER_COLLECTED_AGE_SECONDS = 2_147_483_647


class Heartbeat:
    """When the last cycle whose filesystem snapshot collected finished."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._last: float | None = None
        self._lock = threading.Lock()

    def beat(self) -> None:
        with self._lock:
            self._last = self._clock()

    def age_seconds(self) -> int:
        with self._lock:
            last = self._last
        if last is None:
            return NEVER_COLLECTED_AGE_SECONDS
        return max(0, int(self._clock() - last))


def _handler(node: str, heartbeat: Heartbeat) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path.split("?", 1)[0] != HEALTH_PATH:
                self.send_error(404)
                return
            # Always 200 while the process answers. Staleness is in the body.
            body = json.dumps(
                {"ok": True, "node": node, "last_cycle_age_seconds": heartbeat.age_seconds()},
                separators=(",", ":"),
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            """A probe every few seconds would drown the exporter's own log lines."""

    return Handler


def start_health_server(
    host: str, port: int, node: str, heartbeat: Heartbeat
) -> ThreadingHTTPServer:
    """Serve the endpoint on a daemon thread. Port 0 picks a free one for tests."""
    server = ThreadingHTTPServer((host, port), _handler(node, heartbeat))
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, name="health", daemon=True).start()
    return server
