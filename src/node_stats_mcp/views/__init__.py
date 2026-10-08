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

DISK_URI = "ui://node-stats/disk"
MEMORY_URI = "ui://node-stats/memory"

# Tool name -> the view that charts its result. server.py registers from this.
TOOL_VIEWS = {
    "get_disk_info": DISK_URI,
    "get_memory_info": MEMORY_URI,
}

_KINDS = {DISK_URI: "disk", MEMORY_URI: "memory"}


def tool_meta(tool_name: str) -> dict[str, Any] | None:
    """The `_meta` a tool declares to point a host at its view, or None for no view."""
    uri = TOOL_VIEWS.get(tool_name)
    return {"ui": {"resourceUri": uri}} if uri else None


def render(uri: str, *, warn_percent: float, critical_percent: float) -> str:
    """The self-contained HTML for one view. The shell takes no network access."""
    config = {
        "kind": _KINDS[uri],
        "warnPercent": warn_percent,
        "criticalPercent": critical_percent,
    }
    # `</` would end the inline script block early. The values are ours, not a caller's.
    payload = json.dumps(config).replace("</", "<\\/")
    shell = (files(__package__) / "view.html").read_text(encoding="utf-8")
    return shell.replace("__NODE_STATS_VIEW_CONFIG__", payload)
