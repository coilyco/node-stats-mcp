# node-stats-mcp

A node-local MCP battery. It reads the node it runs on - CPU, memory, Linux contention, disk-pressure runway, block I/O, load, network, top processes, Kubernetes health and storage attribution, scheduled-work freshness, and bounded file metadata - and serves that over MCP (streamable-HTTP).

This is the generic node-introspection spine, first instance of the upstream pattern: a per-node MCP agent, the same shape as node-exporter (DaemonSet-or-node-pinned + hostPath + host namespaces), but exposing a tool surface instead of Prometheus metrics.

## Node view, not pod view

True node stats need the pod to borrow the host's namespaces: **hostPID** so process listings see the node, **hostNetwork** so net counters are the node's, and a read-only **hostPath** of `/` at `/host` (with `ROOTFS=/host`) for disk. CPU and memory come from the non-namespaced `/proc/{stat,meminfo}` regardless. The deploy bundle wires all of this - see below.

## k3s view

The server also exposes a read-only k3s inventory and health surface:

- `get_k3s_pods` - namespace, pod, phase, node, restart count, container names/images, pod IP, age, plus each container's state detail and last state (OOMKilled and its exit code, ImagePullBackOff and the image, the termination behind a crashloop). Init containers listed separately. Narrows by namespace, name, or name prefix at the API.
- `get_k3s_container_memory` - per-container memory from metrics-server when available, else approximate RSS summed from host cgroups.
- `get_k3s_process_attribution` - top host processes annotated with the owning pod/container when cgroup data and pod metadata line up.
- `get_k3s_resource_usage` - bounded kubelet Summary API usage for the selected node, system containers, pods, containers, volumes, and ephemeral storage.
- `get_k3s_node_health` - node conditions, taints, capacity, and recent node-relevant or warning events.
- `get_k3s_volume_usage` - bounded local-volume disk usage and lifecycle state joined to namespaces, PVCs, PVs, and pod/container mount paths, plus unattributed storage directories.
- `get_k3s_scheduled_work` - Jobs and CronJobs with failures, activity, duration, and last-schedule or last-success timing.
- `get_k3s_configured_conditions` - normalized conditions for custom-resource types selected by server configuration, narrowed by namespace, object name, or configured source.
- `get_k3s_workloads` - Deployments, StatefulSets, and DaemonSets with the spec image, replica counts, observedGeneration, and a folded `rollout_complete`.
- `get_k3s_storage_claims` - PersistentVolumeClaims with phase, conditions, and their bound volume.
- `get_k3s_events` - cluster events scoped to a namespace or one object by kind and name, warnings first.
- `get_k3s_namespaces` - namespaces with phase, age, deletion timestamp, and finalizers.
- `get_k3s_network` - Services, Ingresses, and EndpointSlices with ready endpoint counts.
- `get_k3s_logs` - bounded, redacted container logs for one pod, with `previous` for the container that died.

The API read path prefers the host-mounted k3s admin kubeconfig at `/host/etc/rancher/k3s/k3s.yaml` and falls back to the pod's service account when needed. Every tool stays read-only.

## Safety

Read-only by construction: every tool is a read, none mutate the host. File introspection (`stat_path`, `read_text_head`) is **prefix-allowlisted** via `NODE_STATS_READABLE_ROOTS` (empty by default = file reads denied) and size-capped, so a tool can never be walked into `/host/root/.ssh`. Disk pressure scans (`get_pressure_path_usage`) use fixed configured roots and server-discovered immediate children. Kubernetes volume scans resolve API-reported PV paths beneath `NODE_STATS_K3S_VOLUME_ROOTS` and reject every path outside those roots. Freshness markers and custom-resource types are also selected by server configuration. Callers cannot turn these tools into a filesystem or Kubernetes API browser. Reach is gated at the network layer (the tailnet / node), not by the tool.

## Disk pressure

`get_filesystem_pressure` reports root filesystem capacity, available bytes, inode use, and byte runway to configurable warning and critical thresholds. `get_pressure_path_usage` attributes each fixed node-pressure root, such as logs, journald, kubelet, k3s, or containerd storage, to its immediate children. Every child result reports size, entries scanned, permission and scan errors, cross-filesystem skips, timeout, and truncation details. Root discovery is capped by `NODE_STATS_MAX_PRESSURE_CHILDREN_PER_ROOT`. The `limit` argument caps returned children per root, while `max_entries_per_path` caps work per child.

Traversal runs in a worker thread, so fast tools remain responsive. The request divides its total entry and wall-clock budgets across roots and children before scanning, preventing one large storage tree from starving its siblings. Nested configured roots are coalesced, with skipped overlaps reported instead of walking the same subtree twice. Callers select neither roots nor children.

`get_k3s_volume_usage` narrows that disk view to local persistent volumes. It joins Kubernetes pod, PVC, and PV metadata to server-approved host paths, reports pod/container mount points, rolls unique volume bytes up by namespace, and separately reports storage-root children that no current PV owns. Fair entry and time slices keep one large volume from starving its siblings. Volume and namespace results label complete usage versus lower bounds, and the response schedules or exposes the matching complete host-usage snapshot when a profile covers the configured storage root.

`get_host_usage_breakdown` provides the complete drilldown path. A caller
selects only a server-configured profile such as `root`, `var`, `var-lib`,
`k3s`, or `k3s-storage`. The request returns cached state immediately and
starts a missing, stale, or requested refresh on a background thread. Every
snapshot states whether its totals are complete or lower bounds. Mount identity
and exclusions show where different filesystems were skipped and where kubelet
bind mounts were deduplicated.

`get_host_log_usage` scans configured log and journald roots with fixed bounds.
Nested journald roots count once. `get_deleted_open_files` reports
inode-deduplicated deleted descriptors by disk-backed, memfd, tmpfs, device,
container-overlay, and other classes without returning filenames or reading
contents. See [docs/host-storage.md](docs/host-storage.md) for the operator
workflow, snapshot contract, and configuration.

## Contention and freshness

`get_node_pressure_stalls` reads fixed Linux PSI files, selected VM pressure counters, and bounded per-device block I/O counters. It exposes CPU, memory, and I/O stalls plus swap, major-fault, reclaim, and OOM evidence without accepting a path.

`get_configured_freshness` reports whether server-declared success markers are fresh, stale, missing, or affected by clock skew. It returns metadata only, never marker contents. Kubernetes scheduled-work timing and configured custom-resource conditions provide the corresponding cluster view.

## SigNoz export

The same image includes `node-stats-exporter`, a dependency-free OTLP/HTTP JSON exporter intended to run as a sidecar beside the MCP server. It collects the fast contention, kubelet, health, scheduled-work, freshness, configured-condition, and root-filesystem sources every minute by default. The slower local-volume scan runs every 15 minutes by default.

Metrics use stable node, namespace, configured-resource, device, CronJob, freshness-check, and PVC attributes. Pod, container, process, event-object, and generated PV names stay out of metric attributes. One bounded structured log per source retains the detailed snapshot, including pod and event detail. Oversized logs become valid truncation envelopes rather than invalid partial JSON.

The two processes fail independently. Collector errors do not stop collection, and exporter errors cannot take down the MCP server. See [docs/signoz-export.md](docs/signoz-export.md) for the data model, bounds, and configuration.

## Run it locally

```sh
just sync
just run     # streamable-HTTP MCP on :8080, endpoint at /mcp
```

## Commands

Dev commands are declared in the [`justfile`](justfile). Run them as `just <verb>`.

## Image

Every push to canonical `main` publishes the private single-architecture image
`forgejo.coilysiren.me/coilyco-flight-deck/node-stats-mcp:<full-source-sha>`.
The trusted publisher verifies the remote manifest. The deploy repository owns
the separate package-read pull Secret and rolls that exact reference.
The small single-architecture runtime avoids the concurrent-manifest and
large-upload publisher paths.

## See also

- [AGENTS.md](AGENTS.md) - agent operating context for this repo.
- [docs/FEATURES.md](docs/FEATURES.md) - inventory of what ships today.
- [docs/tools-host.md](docs/tools-host.md) and [docs/tools-k3s.md](docs/tools-k3s.md) - every tool, argument, and bound.
- [docs/security.md](docs/security.md) - what the host namespaces buy and what they cost.
- [docs/configuration.md](docs/configuration.md) - environment, roots, and scan limits.
- [docs/signoz-export.md](docs/signoz-export.md) - bounded OTLP metrics and structured logs.
- [docs/host-storage.md](docs/host-storage.md) - mount-aware host usage, log, and deleted-file attribution.
- [.ward/ward.yaml](.ward/ward.yaml) - allowlisted commands + catalog block.
- [coilyco-bridge/deploy `services/node-stats-mcp`](https://forgejo.coilysiren.me/coilyco-bridge/deploy) - the k3s deploy surface.

Cross-reference convention from [features-release-tooling.md](docs/features-release-tooling.md).
