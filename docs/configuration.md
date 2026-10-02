# Configuration

Every setting is an environment variable. Scan budgets are in
[scan configuration](configuration-scans.md) and export settings in
[OTLP export](otlp-export.md).

## Core

- `PORT` (default 8080), `HOST` (default 0.0.0.0).
- `ROOTFS` (default `/`) - where the host root is mounted in the pod (`/host` in the deploy).
- `NODE_STATS_READABLE_ROOTS` - colon-separated read allowlist, interpreted inside `ROOTFS`.
- `NODE_STATS_MAX_READ_BYTES` (default 65536).
- `NODE_STATS_FRESHNESS_CHECKS` (default `[]`) - JSON list of fixed host-marker descriptors. Each object supplies `name`, absolute `path`, and positive `max_age_seconds`.
- `NODE_STATS_DISK_WARN_PERCENT` (default 80).
- `NODE_STATS_DISK_CRITICAL_PERCENT` (default 85).
- [FEATURES.md](FEATURES.md) - the inventory.

## k3s

- `NODE_STATS_KUBECONFIG` (default `/etc/rancher/k3s/k3s.yaml`, interpreted inside `ROOTFS`) - host kubeconfig used for the k3s inventory when present.
- `NODE_STATS_K8S_TIMEOUT_SECONDS` (default 3) - timeout for Kubernetes API reads.
- `NODE_STATS_K3S_NODE_NAME` - optional fixed node for node-health and kubelet-summary reads. A cluster with exactly one node needs no setting.
- `NODE_STATS_K3S_CONDITION_RESOURCES` (default `[]`) - JSON list of fixed custom-resource descriptors. Each object supplies `name`, `group`, `version`, `resource`, and optional `namespace`.
- `NODE_STATS_ALERT_SENTRY_DSN` (default unset) - Sentry DSN the exporter sends not-Ready events to, on its own client. Unset turns the alert off. See [not-ready alerting](not-ready-alerting.md).
- `NODE_STATS_NOTREADY_GRACE_SECONDS` (default 900, bounded 60 to 86400) - how long a `Ready` condition stays false before the first event.
- `NODE_STATS_NOTREADY_RENOTIFY_SECONDS` (default 3600, bounded 300 to 86400) - the gap between repeat events for one resource.
- `NODE_STATS_K3S_VOLUME_ROOTS` (default `/var/lib/rancher/k3s/storage`) - colon-separated fixed roots that may contain local PV paths.
- `NODE_STATS_MAX_K3S_VOLUME_PATHS` (default 1000) - cap on local PV and unattributed child paths considered by one volume-usage request.
