# MCP Apps views

`get_disk_info` and `get_memory_info` each declare a `ui://` chart view, following the MCP Apps extension (spec 2026-01-26, `io.modelcontextprotocol/ui`). A host that renders MCP Apps draws the chart. Every other host gets the same text result it always got.

* **Tool side.** Each tool carries `_meta.ui.resourceUri`, `ui://node-stats/disk` and `ui://node-stats/memory`. No other tool declares one. The result is unchanged, `content` text plus the `structuredContent` FastMCP already emitted.
* **Resource side.** Both URIs are listed and read as `text/html;profile=mcp-app`, with `_meta.ui.prefersBorder` false. `resources/read` renders the page fresh each time.
* **The View.** One self-contained HTML shell, [view.html](../src/node_stats_mcp/views/view.html), takes no network access and no external script, style, or font, because the spec's default CSP is `connect-src 'none'`. It speaks JSON-RPC over `postMessage`: `ui/initialize`, `ui/notifications/initialized`, then draws on `ui/notifications/tool-result`. It follows `theme` from the host context and reports `size-changed`.
* **Disk chart.** One bar per filesystem, fullest first, with ticks at the warning and critical thresholds. The server bakes in its own `NODE_STATS_DISK_WARN_PERCENT` and `NODE_STATS_DISK_CRITICAL_PERCENT` when it serves the page, so the chart and `get_filesystem_pressure` agree. Over a threshold the bar takes the status color and a label says warning or critical. Mounts that share a device and the same numbers collapse to one row.
* **Mounts with no usage are counted, not drawn.** On kai-server, 57 of 60 mounts from `get_disk_info` carry `usage: {}`, so the chart says so under the bars instead of drawing empty ones. The cause is in the tool, not the view.
* **Memory chart.** One stacked bar of in use against available, and one for swap. In use is total minus available, the quantity `percent` is defined by, because psutil's own `used` field differs from it on macOS. Every reported field is in the table view.
* **Every chart has a table view**, a closed details element, so no value rests on color or hover alone.

## Adding a view

The seam is `TOOL_VIEWS` in [views/\_\_init\_\_.py](../src/node_stats_mcp/views/__init__.py). Add the tool name and a `ui://node-stats/<name>` URI, give `view.html` a renderer for that `kind`, and register the resource beside `disk_view` in `server.py`. The tests derive the declared URIs from `tools/list`, so a new view needs no edit to a list in them.

## Checking it

* **Tests** drive a real in-memory client session: `_meta.ui.resourceUri` on the two tools and no others, `resources/read` returning the right MIME type, the thresholds in the page, and the text result unchanged.
* **The View itself** needs a browser. Render it in the ext-apps reference host (`examples/basic-host`) against a local run of the server. A browser host calls the server from the page, and this server sends no CORS headers on purpose, so put a CORS shim in front for the test. The aterm gateway reaches servers from the daemon and needs none.
* **Not covered by a committed check:** the View's rendering. COI-2503 tracks adding one.

## Version floor

`mcp>=1.26.0`. Tool `meta=` arrived in 1.19.0 and resource `meta=` in 1.26.0. The lockfile already resolved 1.28.1.
