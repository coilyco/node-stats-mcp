"""Sentry receives crashes only (teable:coilyco/deploy#8347)."""

from __future__ import annotations

import logging
from typing import Any

import pytest
import sentry_sdk
from sentry_sdk.transport import Transport
from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from node_stats_mcp import crash

DSN = "https://public@example.invalid/1"


class _Capture(Transport):
    def __init__(self) -> None:
        super().__init__()
        self.events: list[Any] = []

    def capture_envelope(self, envelope: Any) -> None:
        event = envelope.get_event()
        if event is not None:
            self.events.append(event)


def _reset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(crash, "_initialized", False)
    monkeypatch.setattr(crash, "_active", False)
    monkeypatch.setattr(crash, "_window", [])


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch) -> Any:
    transport = _Capture()
    real_init = sentry_sdk.init
    monkeypatch.setattr(
        crash.sentry_sdk, "init", lambda **kwargs: real_init(transport=transport, **kwargs)
    )
    _reset(monkeypatch)
    monkeypatch.setenv("SENTRY_DSN", DSN)
    monkeypatch.setenv("NODE_STATS_K3S_NODE_NAME", "node-b")
    yield transport
    real_init()


def _app() -> Starlette:
    async def crashed(_request: Request) -> PlainTextResponse:
        raise RuntimeError("route crashed")

    async def handled(_request: Request) -> PlainTextResponse:
        logging.getLogger("node_stats_mcp.test").error("psutil read failed, returning partial")
        return PlainTextResponse("ok")

    async def refused(_request: Request) -> PlainTextResponse:
        raise HTTPException(status_code=503, detail="deliberate")

    return Starlette(
        routes=[Route("/crash", crashed), Route("/handled", handled), Route("/refused", refused)]
    )


def _values(transport: _Capture) -> list[str]:
    return [event["exception"]["values"][-1]["value"] for event in transport.events]


def test_no_dsn_leaves_sentry_off(monkeypatch: pytest.MonkeyPatch) -> None:
    _reset(monkeypatch)
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    assert crash.init_crash_reporting("mcp_server") is False


def test_an_uncaught_route_exception_reaches_sentry_tagged_by_node(captured: Any) -> None:
    assert crash.init_crash_reporting("mcp_server") is True
    client = TestClient(_app(), raise_server_exceptions=False)
    assert client.get("/crash").status_code == 500
    sentry_sdk.flush()
    assert _values(captured) == ["route crashed"]
    assert captured.events[0]["tags"]["node"] == "node-b"
    assert captured.events[0]["tags"]["component"] == "mcp_server"


def test_handled_errors_stay_out_of_sentry(captured: Any) -> None:
    crash.init_crash_reporting("mcp_server")
    client = TestClient(_app(), raise_server_exceptions=False)
    assert client.get("/handled").status_code == 200
    assert client.get("/refused").status_code == 503
    sentry_sdk.flush()
    assert captured.events == []


def test_the_mcp_integration_annotates_with_pii_off(captured: Any) -> None:
    crash.init_crash_reporting("mcp_server")
    client = sentry_sdk.get_client()
    assert client.get_integration("mcp") is not None
    # The MCP integration records tool arguments and results only with PII on.
    assert client.options["send_default_pii"] is False


def test_budget_caps_events_per_process_minute(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(crash, "_window", [])
    allowed = [crash._within_budget(100.0) for _ in range(crash.SENTRY_EVENTS_PER_MINUTE + 1)]
    assert allowed.count(True) == crash.SENTRY_EVENTS_PER_MINUTE
    assert allowed[-1] is False
    assert crash._within_budget(161.0) is True


def test_init_failure_logs_the_class_and_never_the_dsn(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def refuse(**_kwargs: Any) -> None:
        raise ValueError("https://secret-key@o0.ingest.example/1")

    _reset(monkeypatch)
    monkeypatch.setattr(crash.sentry_sdk, "init", refuse)
    monkeypatch.setenv("SENTRY_DSN", "https://secret-key@o0.ingest.example/1")
    with caplog.at_level(logging.WARNING, logger="node_stats_mcp.crash"):
        assert crash.init_crash_reporting("mcp_server") is False
    assert "ValueError" in caplog.text
    assert "secret-key" not in caplog.text


def test_a_crash_keeps_locals_and_scrubs_process_data(captured: Any) -> None:
    secret = "-".join(["HOST", "SECRET"])

    async def crashed(request: Request) -> PlainTextResponse:
        sample = await request.json()
        tool_name = sample["tool"]  # noqa: F841
        cmdline = sample["cmdline"]  # noqa: F841
        logging.getLogger("node_stats_mcp.test").warning("reading processes")
        raise RuntimeError("route crashed")

    assert crash.init_crash_reporting("mcp_server") is True
    app = Starlette(routes=[Route("/crash", crashed, methods=["POST"])])
    client = TestClient(app, raise_server_exceptions=False)
    body = {"tool": "get_top_processes", "cmdline": ["worker", "--token=" + secret]}
    assert client.post("/crash", json=body).status_code == 500
    sentry_sdk.flush()
    (event,) = captured.events
    assert event["exception"]["values"][-1]["value"] == "route crashed"
    frame_vars = event["exception"]["values"][-1]["stacktrace"]["frames"][-1]["vars"]
    # Locals are what make the trace useful, so a harmless one stays readable.
    assert "get_top_processes" in frame_vars["tool_name"]
    assert secret not in repr(captured.events)
    crumbs = [crumb.get("message") for crumb in event["breadcrumbs"]["values"]]
    assert "reading processes" in crumbs
    assert event["request"]["method"] == "POST"
    assert event["request"]["url"].endswith("/crash")
