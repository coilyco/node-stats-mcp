"""MCP Apps views: `ui://` chart resources that render a tool's own result.

A tool opts in with `_meta.ui.resourceUri`; a host that speaks MCP Apps reads
that resource and draws the result, every other host keeps the text result.
One HTML shell serves every view, with the view kind and the server's disk
thresholds baked in at read time. See docs/mcp-apps-views.md.
"""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

# The only content type the 2026-01-26 spec defines for a View.
RESOURCE_MIME_TYPE = "text/html;profile=mcp-app"

# Tool name -> view kind. The URI, `_meta`, resource and renderer derive from it.
TOOL_KINDS = {
    "get_disk_info": "disk",
    "get_memory_info": "memory",
    "get_system_snapshot": "system",
    "get_cpu_info": "cpu",
    "get_filesystem_pressure": "pressure",
    "get_network_info": "network",
    "get_conntrack": "conntrack",
    "get_k3s_pods": "k3s-pods",
    "get_k3s_workloads": "k3s-workloads",
    "get_k3s_node_health": "k3s-node-health",
}


def uri_for(kind: str) -> str:
    return f"ui://node-stats/{kind}"


DISK_URI = uri_for("disk")
MEMORY_URI = uri_for("memory")

TOOL_VIEWS = {tool: uri_for(kind) for tool, kind in TOOL_KINDS.items()}
_KINDS = {uri_for(kind): kind for kind in TOOL_KINDS.values()}
_TOOLS = {uri_for(kind): tool for tool, kind in TOOL_KINDS.items()}


def tool_meta(tool_name: str) -> dict[str, Any] | None:
    """The `_meta` a tool declares to point a host at its view, or None for no view."""
    uri = TOOL_VIEWS.get(tool_name)
    return {"ui": {"resourceUri": uri}} if uri else None


def render(uri: str, *, warn_percent: float, critical_percent: float) -> str:
    """The self-contained HTML for one view. The shell takes no network access."""
    config = {
        "kind": _KINDS[uri],
        "tool": _TOOLS[uri],
        "warnPercent": warn_percent,
        "criticalPercent": critical_percent,
    }
    # `</` would end the inline script block early. The values are ours, not a caller's.
    payload = json.dumps(config).replace("</", "<\\/")
    shell = (files(__package__) / "view.html").read_text(encoding="utf-8")
    return shell.replace("__NODE_STATS_VIEW_CONFIG__", payload)
