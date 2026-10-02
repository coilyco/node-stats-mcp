# Not-Ready alerting

The exporter sidecar tells Sentry when a configured Kubernetes resource stays not Ready. It replaces SigNoz's "Kubernetes resource not Ready" rule (teable:coilyco/deploy#8693), and keeps that rule's meaning.

* **What counts.** A resource from `NODE_STATS_K3S_CONDITION_RESOURCES` (ExternalSecrets, Certificates, Flux GitRepositories and Kustomizations) with a condition named `Ready` whose status is `False`. `Unknown`, and a resource with no `Ready` condition, are not alerts, as in the old rule.
* **When.** Once the condition has been false for `NODE_STATS_NOTREADY_GRACE_SECONDS` (default 900). Kubernetes' own transition time counts, so an exporter restart does not restart the wait. It repeats every `NODE_STATS_NOTREADY_RENOTIFY_SECONDS` (default 3600) while the resource stays false. A recovery, or a deleted resource, forgets it, and a new failure waits out its own grace.
* **What it sends.** One Sentry error event per resource, tagged `alert=true`, `source=k8s-not-ready`, `node`, `kind`, `namespace` and `name`, fingerprinted by node, kind, namespace and name so repeats join one issue. The condition's reason and message ride along, cut to 300 characters.
* **Where.** `NODE_STATS_ALERT_SENTRY_DSN`, on its own Sentry client. It is the fleet-heartbeats project, where one rule already keys on `alert=true`, so crash reporting's `SENTRY_DSN` stays separate. A malformed DSN stops the exporter at start. An unset one logs `node_stats_not_ready_alerting` with status `off` and nothing alerts.
* **Order.** The alert runs before the OTLP post in each cycle, so a collector that is down cannot silence it.
* **A failed list.** A source whose list returned errors, or a whole conditions collection that failed, leaves the clocks alone. It is never read as recovery.

Each cycle's summary line carries `not_ready_events`, the number sent that cycle.

This is the one handled-error path to Sentry. The per-process crash path stays crash only, and this one sends at most one event per resource per renotify interval.
