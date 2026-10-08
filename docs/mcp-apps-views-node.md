# MCP Apps views: system, pressure, network, k3s

Eight more tools declare a `ui://node-stats/<kind>` view beside disk and memory, on the same shell and with the same guarantees. The shared contract, the handshake, and how to add one are in [MCP Apps views](mcp-apps-views.md). Each view reads `structuredContent` from the tool result and every one has a closed "Table view" details element carrying every value.

* **system** (`get_system_snapshot`) - CPU and memory bars, the three load averages, uptime, logged-in users. Load has no scale without the core count, so the view says so and points at `cpu`.
* **cpu** (`get_cpu_info`) - one bar per logical core, and each load average against the logical core count with a tick at one runnable task per core. No threshold colors, because the server defines none.
* **pressure** (`get_filesystem_pressure`) - the runway the tool exists for: used against the thresholds the result itself carries (`warn_percent`, `critical_percent`), the bytes until or over each, and inode use. The thresholds come from the result, not from the page config, so the chart cannot disagree with the tool. The server defines no inode threshold, so the inode bar has no status color.
* **network** (`get_network_info`) - lifetime bytes per interface, errors and drops printed as lifetime figures, and the filtering block restated in a sentence. See below for movement.
* **conntrack** (`get_conntrack`) - the table fill as a gauge and the counters. When the kernel's stat file is absent the tool says the error totals are UNREAD, and the view prints that note and offers no movement panel, because a panel reading "nothing moved" would look like a clean result.
* **k3s-pods** (`get_k3s_pods`) - a count of Running pods among those returned, then every pod that is not Running and ready with its container reason, exit code, and last state (CrashLoopBackOff, OOMKilled). Completed pods count as healthy. Pods that restarted but are healthy now are named in one line.
* **k3s-workloads** (`get_k3s_workloads`) - ready over desired per workload as a bar, with a flag on any incomplete rollout showing updated replicas and the observed generation. The table lists the spec image.
* **k3s-node-health** (`get_k3s_node_health`) - the node conditions with a mark and a word each (Ready is healthy when True, every other condition when False), taints, cordon state, warning events, and capacity against allocatable in the table.

Counts in the k3s hero lines are over the rows the tool returned, never over `pod_count` or `workload_count`, because those include rows cut by `limit`. A note says when the result was cut.

## Movement for counters

A counter reads as nothing until it moves ([networking tools](tools-network.md)), and one tool call is one reading. When the host advertises `serverTools` at `ui/initialize`, the **network** and **conntrack** views offer a "Watch movement" button. It sends `tools/call` for the same tool, with the arguments the host passed in `ui/notifications/tool-input`, through the host over `postMessage`. The page opens no connection of its own, so `connect-src 'none'` still holds.

* **Cadence and bound.** One reading every five seconds, at most 24, one call in flight at a time. Teardown and a new result stop it.
* **Rates.** Bytes per second between consecutive readings, as a column strip per direction, timed by when the reply arrived.
* **Moves.** Error and drop counters are shown as the increase since the first reading the view was opened with, and a movement is named in text. A counter that goes backward is a reset and shows no movement.
* **Host without serverTools.** The panel says it cannot take a second reading and to call the tool twice.

## Not yet viewed

The other k3s tools (events, volume usage, storage claims, network, namespaces, scheduled work, logs, container memory, process attribution, resource usage), `get_node_pressure_stalls`, `get_top_processes`, and `get_socket_states` keep the text result only. COI-2536 tracks them.
