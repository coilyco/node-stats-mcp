"""MCP Apps views: what a host sees over the wire, through a real client session.

The tests drive tools/list, resources/list, resources/read and tools/call the way
a host does, so they assert the protocol surface and not the Python attributes.
The View's own behavior is not covered here: it needs a browser, and the proof of
it is a render in the ext-apps reference host (docs/mcp-apps-views.md).
"""

from __future__ import annotations

import asyncio
import importlib
import json
from collections import namedtuple
from collections.abc import Awaitable, Callable
from types import ModuleType
from typing import Any

import pytest
from mcp import ClientSession
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import TextContent, TextResourceContents
from pydantic import AnyUrl

MIME = "text/html;profile=mcp-app"


def _load(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.setenv("NODE_STATS_DISK_WARN_PERCENT", "70")
    monkeypatch.setenv("NODE_STATS_DISK_CRITICAL_PERCENT", "90")
    import node_stats_mcp.server as server

    return importlib.reload(server)


def _with_client[T](server: ModuleType, body: Callable[[ClientSession], Awaitable[T]]) -> T:
    async def run() -> T:
        async with create_connected_server_and_client_session(server.mcp._mcp_server) as client:
            return await body(client)

    return asyncio.run(run())


def _ui_uri(tool: Any) -> str | None:
    return ((tool.meta or {}).get("ui") or {}).get("resourceUri")


def test_disk_and_memory_tools_declare_their_view(monkeypatch: pytest.MonkeyPatch) -> None:
    server = _load(monkeypatch)

    async def body(client: ClientSession) -> dict[str, str | None]:
        return {t.name: _ui_uri(t) for t in (await client.list_tools()).tools}

    declared = _with_client(server, body)

    assert declared["get_disk_info"] == "ui://node-stats/disk"
    assert declared["get_memory_info"] == "ui://node-stats/memory"
    # Every other tool stays text-only: a host that sees no _meta.ui draws nothing.
    assert {n for n, uri in declared.items() if uri} == {"get_disk_info", "get_memory_info"}


def test_every_declared_view_is_a_listed_resource_that_reads_as_mcp_app_html(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = _load(monkeypatch)

    async def body(client: ClientSession) -> tuple[set[str], dict[str, list[Any]], dict[str, str]]:
        uris = {u for t in (await client.list_tools()).tools if (u := _ui_uri(t))}
        listed = {str(r.uri): r for r in (await client.list_resources()).resources}
        reads = {u: (await client.read_resource(AnyUrl(u))).contents for u in uris}
        return uris, reads, {u: listed[u].mimeType or "" for u in uris}

    uris, reads, listed_mime = _with_client(server, body)

    assert uris == {"ui://node-stats/disk", "ui://node-stats/memory"}
    for uri in uris:
        assert listed_mime[uri] == MIME
        (content,) = reads[uri]
        assert isinstance(content, TextResourceContents)
        assert content.mimeType == MIME
        assert content.text.lower().startswith("<!doctype html>")
        assert "__NODE_STATS_VIEW_CONFIG__" not in content.text


def test_view_carries_the_servers_own_thresholds_not_a_copy_of_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = _load(monkeypatch)

    async def body(client: ClientSession) -> str:
        (content,) = (await client.read_resource(AnyUrl("ui://node-stats/disk"))).contents
        assert isinstance(content, TextResourceContents)
        return content.text

    html = _with_client(server, body)

    assert '"kind": "disk"' in html
    assert '"warnPercent": 70.0' in html
    assert '"criticalPercent": 90.0' in html


def test_view_asks_the_network_for_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """The spec's default CSP is connect-src 'none' and no external scripts or styles."""
    server = _load(monkeypatch)

    async def body(client: ClientSession) -> list[str]:
        out = []
        for uri in ("ui://node-stats/disk", "ui://node-stats/memory"):
            (content,) = (await client.read_resource(AnyUrl(uri))).contents
            assert isinstance(content, TextResourceContents)
            out.append(content.text)
        return out

    for html in _with_client(server, body):
        assert "http://" not in html
        assert "https://" not in html
        assert "@import" not in html


def test_text_result_is_unchanged_and_is_what_the_view_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = _load(monkeypatch)
    Virtual = namedtuple("Virtual", "total available percent used free")
    Swap = namedtuple("Swap", "total used free percent sin sout")
    monkeypatch.setattr(server.psutil, "virtual_memory", lambda: Virtual(100, 40, 60.0, 60, 10))
    monkeypatch.setattr(server.psutil, "swap_memory", lambda: Swap(50, 5, 45, 10.0, 0, 0))

    async def body(client: ClientSession) -> Any:
        return await client.call_tool("get_memory_info", {})

    result = _with_client(server, body)

    (block,) = result.content
    assert isinstance(block, TextContent)
    assert json.loads(block.text) == server.get_memory_info()
    assert result.structuredContent == server.get_memory_info()
    assert not result.isError
