# node-stats-mcp features

Living inventory of what ships here: a read-only MCP server over host and k3s
diagnostics, with an OTLP exporter.

## Tools

All read-only: 33 host and node tools in [host tools](tools-host.md) and 14
cluster tools in [k3s tools](tools-k3s.md), covering CPU, memory, disk,
filesystem and PSI pressure, usage attribution, deleted open files, network,
processes, and the k3s pod, workload, storage, event, namespace, network,
volume, scheduling, and health views.

The cluster tools cover the read-only `kubectl` surface a live investigation
reaches for: container failure reasons and exit codes, workload rollout state
against the spec image, claim binding, object-scoped events, routing and ready
endpoints, and bounded container logs. Every one narrows by namespace at the
API rather than returning the cluster.

A [networking surface](tools-network.md) covers connection tracking, TCP socket
states, ephemeral port usage, and the node and pod DNS resolvers, with
per-interface filtering so a k3s node's per-pod veth churn does not bury the
interfaces that carry traffic. It also states which of its readings are
cumulative counters and which are instantaneous gauges, because only a
counter's movement is interpretable and a gauge sampled coarsely reads clean
through the event it was meant to catch.

## OTLP export

A same-image `node-stats-exporter` sidecar runs independently of the MCP
process, on fast and slow cadences, emitting stable metric dimensions and
bounded structured logs over independent signals. See
[OTLP export](otlp-export.md).

## Security and configuration

Read-only by construction, an allowlisted read surface, and bounded traversal:
[security](security.md). Settings are environment-only, in
[configuration](configuration.md) and
[scan configuration](configuration-scans.md).

## Deploy

Every push to canonical `main` publishes and verifies the private image at a
full source SHA. Rollout lives in
[deploy](https://forgejo.coilysiren.me/coilyco-bridge/deploy).

## See also

- [../README.md](../README.md) - human-facing intro.
- [../AGENTS.md](../AGENTS.md) - agent operating context.
- [../.ward/ward.yaml](../.ward/ward.yaml) - allowlisted commands + catalog block.

Cross-reference convention from [features-release-tooling.md](features-release-tooling.md).
