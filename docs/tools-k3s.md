# k3s tools

Read-only views of the local k3s cluster. Host and node tools are in
[host tools](tools-host.md).

- **get_k3s_pods** - namespace/pod/container inventory, narrowed at the API by namespace, name, or name prefix. Each container carries `state_detail` and `last_state`, which name OOMKilled and its exit code, ImagePullBackOff and the image, and the termination behind a crashloop. Init containers are listed separately so an `Init:CrashLoopBackOff` stays a distinct diagnosis. Not-Running pods sort first.
- **get_k3s_container_memory** - approximate per-container memory from metrics-server or host cgroups.
- **get_k3s_process_attribution** - top host processes annotated with namespace/pod/container when cgroup metadata resolves.
- **get_k3s_resource_usage** - worker-thread kubelet Summary API view of node, runtime filesystem, system-container, pod, container, volume, network, and ephemeral-storage usage.
- **get_k3s_node_health** - worker-thread node conditions, taints, capacity, allocatable resources, and recent relevant or warning events.
- **get_k3s_volume_usage** - worker-thread local-volume scan joined to namespaces, PVCs, PVs, pod/container mount paths, and storage lifecycle state. Namespace totals count each volume once, server-owned roots constrain every scan, fair per-volume budgets prevent starvation, and unowned root children remain visible as unattributed storage. Volume, namespace, and response totals label complete usage versus lower bounds, while a matching host-usage profile schedules or exposes the complete background snapshot.
- **get_k3s_scheduled_work** - worker-thread Jobs and CronJobs with activity, failure, duration, and last-schedule or last-success timing.
- **get_k3s_configured_conditions** - normalized conditions from server-configured Kubernetes custom-resource types, narrowed by namespace, object name, or configured source. Callers select among configured types and can never name a new one.
- **get_k3s_workloads** - Deployments, StatefulSets, and DaemonSets with the **spec** image, desired/ready/updated/available replicas, observedGeneration, and a folded `rollout_complete`. The spec image is a different fact from the running pod image, and they diverge exactly when a rollout was applied and has not landed.
- **get_k3s_storage_claims** - PersistentVolumeClaims with phase, conditions, and their bound PersistentVolume. The lifecycle view beside get_k3s_volume_usage, which measures disk rather than answering whether a claim bound.
- **get_k3s_events** - cluster events scoped to a namespace or to one object by kind and name, warnings first.
- **get_k3s_namespaces** - namespaces with phase, age, deletion timestamp, and the finalizers holding a stuck Terminating one.
- **get_k3s_network** - Services, Ingresses, and EndpointSlices. `ready_endpoint_count` is how a Service that resolves and answers nothing becomes visible.
- **get_k3s_logs** - bounded, redacted container logs for one pod, with `previous` for the container that died. See [security](security.md) for the exposure bound.
