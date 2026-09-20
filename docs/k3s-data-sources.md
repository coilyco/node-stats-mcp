# k3s data sources

Where the k3s tools read from, and what each falls back to.

- The preferred path is the host-mounted k3s admin kubeconfig at `/host/etc/rancher/k3s/k3s.yaml`.
- If that file is unavailable, the server falls back to the pod's service account token.
- Container memory prefers `metrics.k8s.io`, then falls back to cgroup-backed RSS from host PID data.
- Kubelet summary and node health select `NODE_STATS_K3S_NODE_NAME` when configured. Without it, those reads require the Kubernetes API to return exactly one node.
- Node events include events attached to the selected node or its pods, plus bounded recent warning events for cluster resources.
- Volume attribution joins the core pod, PVC, and PV APIs. The scanner measures only PV paths beneath `NODE_STATS_K3S_VOLUME_ROOTS`.
- Volume lifecycle includes PVC/PV phase, deletion timestamp, finalizers, conditions, access modes, volume mode, reclaim policy, and PV status details.
- Namespace totals count each local volume once even when multiple pods mount the same claim.
- Unattributed results are immediate children of the configured storage roots that no current PV path owns. They surface released or abandoned local-path data without guessing ownership.
- Scheduled-work freshness comes from the batch/v1 Job and CronJob APIs.
- Custom-resource condition sources come from `NODE_STATS_K3S_CONDITION_RESOURCES`, a JSON list of objects with `name`, `group`, `version`, `resource`, and optional `namespace`.
- Pod, workload, claim, event, namespace, and network reads narrow by namespace at the API path rather than filtering a cluster-wide list locally. A selector is validated against the DNS-subdomain grammar before it is interpolated into a request path.
- Workload reads come from the apps/v1 Deployment, StatefulSet, and DaemonSet APIs; network reads from core/v1 Services, networking.k8s.io/v1 Ingresses, and discovery.k8s.io/v1 EndpointSlices.
- Container logs come from the core/v1 pod log subresource, which returns text rather than JSON, and are capped at the socket by `NODE_STATS_K3S_LOG_MAX_BYTES`.
