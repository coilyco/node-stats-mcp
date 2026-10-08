# Host and node tools

Every tool is read-only. The k3s tools are in [k3s tools](tools-k3s.md).

- **get_cpu_info** - utilization, logical/physical core counts, per-core percentages, load average. Declares a view, see [MCP Apps views](mcp-apps-views-node.md).
- **get_memory_info** - virtual and swap memory (bytes + percent). Declares a chart view, see [MCP Apps views](mcp-apps-views.md).
- **get_disk_info** - per-partition usage, filesystem type, and mount options with a `quota_enforced` flag, resolved under `ROOTFS`. Options are where a per-directory ceiling is visible: without them, directories sharing one filesystem look identical to filesystems with separate capacities. Declares a chart view, see [MCP Apps views](mcp-apps-views.md).
- **get_filesystem_pressure** - root filesystem capacity, available bytes, inode pressure, and byte runway to warning/critical thresholds. Declares a view, see [MCP Apps views](mcp-apps-views-node.md).
- **get_node_pressure_stalls** - fixed Linux PSI, selected VM pressure, and bounded per-device block I/O counters.
- **get_pressure_path_usage** - worker-thread one-level attribution beneath configured node-pressure roots such as logs, journald, kubelet, k3s, and containerd storage. Every discovered child receives a fair entry and time slice, preventing a large root or child from starving siblings. Per-child results include size, entries scanned, permission/scan errors, skipped different-filesystem entries, and timeout/truncation metadata.
- **get_host_usage_breakdown** - background snapshots for fixed profiles. Mount identity, filesystem exclusions, bind-mount deduplication, allocated and apparent bytes, freshness, errors, and explicit complete-versus-lower-bound state support a root-to-owner drilldown without a raw path.
- **get_host_log_usage** - allocated usage for fixed log and journald roots. Nested journald roots are excluded from parent scans and counted separately.
- **get_deleted_open_files** - worker-thread `/proc` metadata summary that deduplicates open inodes and separates disk-backed reclaimable files from linked, memfd, tmpfs, device, container-overlay, and other non-disk entries. Filenames and file contents are not returned.
- **get_network_info** - aggregate and per-interface I/O counters, filtered to drop per-pod veth churn (node-wide under hostNetwork). See [networking tools](tools-network.md). Declares a view that can watch counter movement, see [MCP Apps views](mcp-apps-views-node.md).
- **get_conntrack** - netfilter connection tracking count against max, plus every per-CPU error column the kernel publishes, summed by name. See [networking tools](tools-network.md). Declares a view, see [MCP Apps views](mcp-apps-views-node.md).
- **get_socket_states** - TCP socket counts by state, the constant-cost sockstat summary, and ephemeral port usage against the configured range. See [networking tools](tools-network.md).
- **get_resolver** - the node's DNS resolver, and optionally a pod's own as the container sees it. See [networking tools](tools-network.md).
- **get_top_processes** - top N by cpu or memory (node-wide under hostPID).
- **get_configured_freshness** - metadata-only freshness state for server-configured host success markers.
- **get_system_snapshot** - one-shot overview: cpu, memory, load, boot time, uptime, logged-in users. Declares a view, see [MCP Apps views](mcp-apps-views-node.md).
- **stat_path** - size/mode/mtime/type for a path under the readable-root allowlist.
- **read_text_head** - up to `max_bytes` (capped) of a text file under the allowlist.
