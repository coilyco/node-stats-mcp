# Exporter health endpoint

`GET /healthz` on the exporter sidecar says how long ago a cycle last collected the filesystem snapshot. Gatus probes it (`teable:coilyco/deploy#8704`), replacing the SigNoz rules that fired when the exporter's own metrics went quiet.

* **Off by default.** `NODE_STATS_HEALTH_PORT` turns it on, a port from 1 to 65535. A bad value stops the exporter at start. `--once` and `--dry-run` never bind it.
* **Binds `0.0.0.0`.** The MCP port is served the same way on both nodes, and the body holds no secret. A port already taken logs `node_stats_health_endpoint` with status `error` and the exporter keeps exporting.
* **Always 200 while the process answers.** Staleness is in the body, so a probe gates on the number and a refused connection means the process is down.

```json
{"ok": true, "node": "kai-server", "last_cycle_age_seconds": 42}
```

* **`last_cycle_age_seconds`.** Whole seconds since the last cycle whose `filesystem` source collected without a `collection_error`. A cycle where it failed, or never ran, leaves the age growing.
* **Before the first such cycle** it is `2147483647`, never null or absent. A probe checking `< 900` on a missing field would pass, so the field is always there.
* **What it does not see.** The age is taken at collection, before the OTLP post, so a collector that is down does not move it. The cycle summary line's `errors` carry that.
* **Other paths** return 404.
