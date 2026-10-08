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
* **The View itself** runs in a real browser: `just browser-install` once, then `just check-views`. CI runs both before it publishes. [test_views_browser.py](../tests/test_views_browser.py) is a stand-in host page that embeds each View's HTML from `resources/read` in a sandboxed iframe under `default-src 'none'`, answers `ui/initialize` and `tools/call`, and sends `tool-result`. It asserts on the DOM: the handshake, drawing from `structuredContent` and from the text block, the disk dedupe and the "N of M mounts reported no usage" line, the warning and critical states, the table view, theme from the host and from the OS, `size-changed`, and the error and cancelled messages. Any console error, page error, or request beyond the host page fails the run, so a CSP violation cannot pass quietly. The run is deselected from `just test` by the `browser` marker because it needs a downloaded Chromium, and a missing browser fails it rather than skipping.
* **Playwright is a dev-group dependency only.** The wheel carries its own driver, so the image needs no Node, and the production image installs with `--no-dev`. Chromium comes from `playwright install` at job time (about 115 MiB), not from the shared dev-base image.

A new view adds one entry to `VIEW_FIXTURES` in that file, a callable returning the tool's `structuredContent` shaped like live output. `test_every_declared_view_has_a_fixture` fails and names any declared view without one, and every fixture runs the handshake, table view, and theme tests with no further edit. A View that resamples a counter asks the stand-in host with `tools/call`, answered from `Host.tool_results(name, [result, ...])`.

## Version floor

`mcp>=1.26.0`. Tool `meta=` arrived in 1.19.0 and resource `meta=` in 1.26.0. The lockfile already resolved 1.28.1.
