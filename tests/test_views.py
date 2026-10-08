"""MCP Apps views: what a host sees over the wire, through a real client session.

The tests drive tools/list, resources/list, resources/read and tools/call the way
a host does, so they assert the protocol surface and not the Python attributes.
The View's own behavior is not covered here: it needs a browser, and the proof of
it is a render in the ext-apps reference host (docs/mcp-apps-views.md).
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
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


def _declared(server: ModuleType) -> dict[str, str]:
    async def body(client: ClientSession) -> dict[str, str | None]:
        return {t.name: _ui_uri(t) for t in (await client.list_tools()).tools}

    return {name: uri for name, uri in _with_client(server, body).items() if uri}


def test_every_view_tool_declares_its_view_and_no_other_tool_does(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from node_stats_mcp import views

    server = _load(monkeypatch)

    declared = _declared(server)

    # tools/list is what a host sees. A tool missing here is text-only, which is
    # the right state for every tool the table does not name.
    assert declared == views.TOOL_VIEWS
    assert declared["get_disk_info"] == "ui://node-stats/disk"
    assert declared["get_memory_info"] == "ui://node-stats/memory"
    assert len(set(declared.values())) == len(declared)


def test_every_declared_view_is_a_listed_resource_that_reads_as_mcp_app_html(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = _load(monkeypatch)

    expected = set(_declared(server).values())

    async def body(client: ClientSession) -> tuple[set[str], dict[str, list[Any]], dict[str, str]]:
        uris = {u for t in (await client.list_tools()).tools if (u := _ui_uri(t))}
        listed = {str(r.uri): r for r in (await client.list_resources()).resources}
        reads = {u: (await client.read_resource(AnyUrl(u))).contents for u in uris}
        return uris, reads, {u: listed[u].mimeType or "" for u in uris}

    uris, reads, listed_mime = _with_client(server, body)

    assert uris == expected
    assert len(uris) >= 10
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


def test_each_view_names_its_own_kind_and_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    """One shell serves every view, so the baked-in config is all that tells them apart."""
    server = _load(monkeypatch)
    declared = _declared(server)

    async def body(client: ClientSession) -> dict[str, str]:
        out = {}
        for tool, uri in declared.items():
            (content,) = (await client.read_resource(AnyUrl(uri))).contents
            assert isinstance(content, TextResourceContents)
            out[tool] = content.text
        return out

    for tool, html in _with_client(server, body).items():
        kind = declared[tool].rsplit("/", 1)[1]
        assert f'"kind": "{kind}"' in html
        assert f'"tool": "{tool}"' in html


def test_view_asks_the_network_for_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """The spec's default CSP is connect-src 'none' and no external scripts or styles."""
    server = _load(monkeypatch)
    uris = sorted(_declared(server).values())

    async def body(client: ClientSession) -> list[str]:
        out = []
        for uri in uris:
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


def test_every_view_tool_keeps_its_text_result_and_structured_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Declaring a view must not change what a host without MCP Apps receives."""
    server = _load(monkeypatch)
    # No cluster here, so the k3s tools run their no-API path: empty lists plus errors.
    monkeypatch.setattr(server, "_k8s_list", lambda path: ([], []))
    tools = sorted(_declared(server))

    async def body(client: ClientSession) -> dict[str, tuple[Any, Any]]:
        out = {}
        for name in tools:
            direct = getattr(server, name)()
            if inspect.isawaitable(direct):
                direct = await direct
            out[name] = (await client.call_tool(name, {}), direct)
        return out

    results = _with_client(server, body)

    assert len(results) >= 10
    for name, (result, direct) in results.items():
        assert not result.isError, name
        (block,) = result.content
        assert isinstance(block, TextContent)
        text_payload = json.loads(block.text)
        assert isinstance(text_payload, dict), name
        assert result.structuredContent == text_payload, name
        # Same keys as a direct call. The values drift between calls.
        assert set(text_payload) == set(direct), name
