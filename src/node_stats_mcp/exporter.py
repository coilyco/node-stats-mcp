"""Bounded periodic export of node-stats snapshots over OTLP/HTTP JSON."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import sys
import time
from collections import Counter, defaultdict
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

from node_stats_mcp import server
from node_stats_mcp.crash import init_crash_reporting
from node_stats_mcp.notready import NotReadyWatch, sender_from_env
from node_stats_mcp.notready import load_config as load_notready_config
from node_stats_mcp.otlp import (
    AttributeValue,
    LogRecord,
    MetricPoint,
    encode_request,
    logs_request,
    metrics_request,
    post_json,
    signal_url,
)

PostJson = Callable[[str, bytes, float], int]


@dataclass(frozen=True)
class ExportConfig:
    """Server-owned exporter settings with defensive bounds."""

    endpoint: str
    interval_seconds: int
    volume_interval_seconds: int
    limit: int
    max_log_bytes: int
    max_payload_bytes: int
    max_metric_points: int
    timeout_seconds: float


@dataclass(frozen=True)
class CycleResult:
    """Observable outcome from one independent collection and export cycle."""

    source_count: int
    metric_point_count: int
    log_record_count: int
    dropped_metric_points: int
    dropped_log_records: int
    included_volume: bool
    duration_seconds: float
    metrics_status: int | None
    logs_status: int | None
    errors: tuple[str, ...]
    not_ready_events: int = 0

    @property
    def succeeded(self) -> bool:
        return not self.errors


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    return max(minimum, min(value, maximum))


def _bounded_float(name: str, default: float, minimum: float, maximum: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc
    return max(minimum, min(value, maximum))


def load_config(*, require_endpoint: bool = True) -> ExportConfig:
    """Load the exporter configuration without allowing unbounded work."""
    endpoint = os.environ.get("NODE_STATS_OTLP_ENDPOINT", "").strip()
    if require_endpoint and not endpoint:
        raise ValueError("NODE_STATS_OTLP_ENDPOINT is required")
    if endpoint:
        signal_url(endpoint, "metrics")
    interval = _bounded_int("NODE_STATS_EXPORT_INTERVAL_SECONDS", 60, 15, 3600)
    volume_interval = _bounded_int(
        "NODE_STATS_EXPORT_VOLUME_INTERVAL_SECONDS",
        900,
        interval,
        86400,
    )
    max_payload = _bounded_int(
        "NODE_STATS_EXPORT_MAX_PAYLOAD_BYTES",
        1_048_576,
        65_536,
        4_194_304,
    )
    max_log = _bounded_int(
        "NODE_STATS_EXPORT_MAX_LOG_BYTES",
        262_144,
        2_048,
        min(1_048_576, max_payload),
    )
    return ExportConfig(
        endpoint=endpoint,
        interval_seconds=interval,
        volume_interval_seconds=max(interval, volume_interval),
        limit=_bounded_int("NODE_STATS_EXPORT_LIMIT", 50, 1, 100),
        max_log_bytes=max_log,
        max_payload_bytes=max_payload,
        max_metric_points=_bounded_int(
            "NODE_STATS_EXPORT_MAX_METRIC_POINTS",
            2_000,
            100,
            5_000,
        ),
        timeout_seconds=_bounded_float("NODE_STATS_OTLP_TIMEOUT_SECONDS", 5.0, 1.0, 30.0),
    )


async def collect_sources(limit: int, *, include_volume: bool) -> dict[str, dict[str, Any]]:
    """Collect independent bounded sources concurrently and preserve partial results."""
    collectors: list[tuple[str, Awaitable[dict[str, Any]]]] = [
        ("contention", asyncio.to_thread(server.get_node_pressure_stalls, limit)),
        ("kubelet", server.get_k3s_resource_usage(limit)),
        ("health", server.get_k3s_node_health(limit, 24)),
        ("scheduled_work", server.get_k3s_scheduled_work(limit)),
        ("freshness", asyncio.to_thread(server.get_configured_freshness)),
        ("conditions", server.get_k3s_configured_conditions(limit)),
        ("filesystem", asyncio.to_thread(server.get_filesystem_pressure)),
    ]
    if include_volume:
        collectors.append(
            (
                "volumes",
                asyncio.to_thread(
                    server._k3s_volume_usage,
                    limit,
                    server._MAX_DU_ENTRIES,
                    schedule_host_snapshot=False,
                ),
            )
        )
    values = await asyncio.gather(
        *(collector for _, collector in collectors),
        return_exceptions=True,
    )
    snapshots: dict[str, dict[str, Any]] = {}
    for (name, _), value in zip(collectors, values, strict=True):
        if isinstance(value, BaseException):
            message = f"{type(value).__name__}: {value}"[:500]
            snapshots[name] = {
                "collection_error": message,
                "errors": [message],
            }
        else:
            snapshots[name] = value
    return snapshots


def _number(value: Any) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return value


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _point(
    points: list[MetricPoint],
    name: str,
    value: Any,
    *,
    unit: str = "1",
    attributes: dict[str, AttributeValue] | None = None,
    kind: str = "gauge",
) -> None:
    number = _number(value)
    if number is None:
        return
    points.append(
        MetricPoint(
            name=name,
            value=number,
            unit=unit,
            attributes=attributes or {},
            kind="sum" if kind == "sum" else "gauge",
        )
    )


def _condition_value(value: Any) -> int:
    normalized = str(value).lower()
    if normalized == "true":
        return 1
    if normalized == "false":
        return 0
    return -1


def _error_count(value: Mapping[str, Any]) -> int:
    count = len(value.get("errors", [])) if isinstance(value.get("errors"), list) else 0
    for source in _items(value.get("sources")):
        if isinstance(source.get("errors"), list):
            count += len(source["errors"])
    return count


def _contention_points(points: list[MetricPoint], snapshot: Mapping[str, Any]) -> None:
    for resource, scopes in _mapping(snapshot.get("pressure_stall_information")).items():
        for scope, values in _mapping(scopes).items():
            for window in ("avg10", "avg60", "avg300"):
                _point(
                    points,
                    "node_stats.linux.psi.stall",
                    _mapping(values).get(window),
                    unit="%",
                    attributes={
                        "resource": str(resource),
                        "scope": str(scope),
                        "window": window,
                    },
                )
            _point(
                points,
                "node_stats.linux.psi.stall_time",
                _mapping(values).get("total"),
                unit="us",
                attributes={"resource": str(resource), "scope": str(scope)},
                kind="sum",
            )
    for counter, value in _mapping(snapshot.get("vm_pressure_counters")).items():
        _point(
            points,
            "node_stats.linux.vm.events",
            value,
            attributes={"event": str(counter)},
            kind="sum",
        )
    for device in _items(snapshot.get("block_devices")):
        device_name = str(device.get("device") or "unknown")
        for operation in ("read", "write"):
            _point(
                points,
                "node_stats.linux.block_io.bytes",
                device.get(f"{operation}_bytes"),
                unit="By",
                attributes={"device": device_name, "operation": operation},
                kind="sum",
            )
            _point(
                points,
                "node_stats.linux.block_io.operations",
                device.get(f"{operation}_count"),
                attributes={"device": device_name, "operation": operation},
                kind="sum",
            )
        _point(
            points,
            "node_stats.linux.block_io.busy_time",
            device.get("busy_time"),
            unit="ms",
            attributes={"device": device_name},
            kind="sum",
        )


def _filesystem_field_points(
    points: list[MetricPoint],
    values: Mapping[str, Any],
    filesystem: str,
) -> None:
    for state in ("availableBytes", "capacityBytes", "usedBytes"):
        _point(
            points,
            "node_stats.kubelet.filesystem",
            values.get(state),
            unit="By",
            attributes={"filesystem": filesystem, "state": state},
        )
    for state in ("inodesFree", "inodes", "inodesUsed"):
        _point(
            points,
            "node_stats.kubelet.filesystem.inodes",
            values.get(state),
            attributes={"filesystem": filesystem, "state": state},
        )


def _resource_usage_points(points: list[MetricPoint], snapshot: Mapping[str, Any]) -> None:
    node = _mapping(snapshot.get("node"))
    cpu = _mapping(node.get("cpu"))
    usage_nanocores = _number(cpu.get("usageNanoCores"))
    if usage_nanocores is not None:
        _point(
            points,
            "node_stats.kubelet.cpu.usage",
            usage_nanocores / 1_000_000_000,
            unit="{cpu}",
            attributes={"scope": "node"},
        )
    for state in ("availableBytes", "usageBytes", "workingSetBytes", "rssBytes"):
        _point(
            points,
            "node_stats.kubelet.memory",
            _mapping(node.get("memory")).get(state),
            unit="By",
            attributes={"scope": "node", "state": state},
        )
    _filesystem_field_points(points, _mapping(node.get("filesystem")), "node")
    runtime = _mapping(node.get("runtime"))
    _filesystem_field_points(
        points,
        _mapping(runtime.get("image_filesystem")),
        "image",
    )
    _filesystem_field_points(
        points,
        _mapping(runtime.get("container_filesystem")),
        "container",
    )
    _point(points, "node_stats.kubernetes.pods", snapshot.get("pod_count"))

    rollups: dict[str, dict[str, float]] = defaultdict(
        lambda: {
            "pod_count": 0.0,
            "cpu_nanocores": 0.0,
            "memory_bytes": 0.0,
            "ephemeral_bytes": 0.0,
        }
    )
    for pod in _items(snapshot.get("pods")):
        namespace = str(pod.get("namespace") or "default")
        rollup = rollups[namespace]
        rollup["pod_count"] += 1
        rollup["cpu_nanocores"] += float(
            _number(_mapping(pod.get("cpu")).get("usageNanoCores")) or 0
        )
        rollup["memory_bytes"] += float(
            _number(_mapping(pod.get("memory")).get("workingSetBytes")) or 0
        )
        rollup["ephemeral_bytes"] += float(
            _number(_mapping(pod.get("ephemeral_storage")).get("usedBytes")) or 0
        )
    for namespace, rollup in sorted(rollups.items()):
        attributes: dict[str, AttributeValue] = {"namespace": namespace}
        _point(
            points,
            "node_stats.kubernetes.namespace.pods",
            int(rollup["pod_count"]),
            attributes=attributes,
        )
        _point(
            points,
            "node_stats.kubernetes.namespace.cpu.usage",
            rollup["cpu_nanocores"] / 1_000_000_000,
            unit="{cpu}",
            attributes=attributes,
        )
        _point(
            points,
            "node_stats.kubernetes.namespace.memory.working_set",
            int(rollup["memory_bytes"]),
            unit="By",
            attributes=attributes,
        )
        _point(
            points,
            "node_stats.kubernetes.namespace.ephemeral_storage.used",
            int(rollup["ephemeral_bytes"]),
            unit="By",
            attributes=attributes,
        )


def _health_points(points: list[MetricPoint], snapshot: Mapping[str, Any]) -> None:
    node = _mapping(snapshot.get("node"))
    _point(
        points,
        "node_stats.kubernetes.node.schedulable",
        0 if node.get("unschedulable") else 1,
    )
    _point(
        points,
        "node_stats.kubernetes.node.taints",
        len(node.get("taints", [])) if isinstance(node.get("taints"), list) else 0,
    )
    for condition in _items(node.get("conditions")):
        _point(
            points,
            "node_stats.kubernetes.node.condition",
            _condition_value(condition.get("status")),
            attributes={"condition": str(condition.get("type") or "unknown")},
        )
    event_counts: Counter[tuple[str, str]] = Counter()
    for event in _items(snapshot.get("events")):
        key = (
            str(event.get("type") or "Unknown"),
            str(event.get("reason") or "Unknown"),
        )
        event_counts[key] += int(_number(event.get("count")) or 1)
    for (event_type, reason), count in sorted(event_counts.items()):
        _point(
            points,
            "node_stats.kubernetes.events",
            count,
            attributes={"type": event_type, "reason": reason},
        )


def _scheduled_work_points(points: list[MetricPoint], snapshot: Mapping[str, Any]) -> None:
    job_rollups: dict[str, Counter[str]] = defaultdict(Counter)
    for job in _items(snapshot.get("jobs")):
        namespace = str(job.get("namespace") or "default")
        job_rollups[namespace]["jobs"] += 1
        for state in ("active", "succeeded", "failed"):
            job_rollups[namespace][state] += int(_number(job.get(state)) or 0)
    for namespace, states in sorted(job_rollups.items()):
        for state, count in sorted(states.items()):
            _point(
                points,
                "node_stats.kubernetes.jobs",
                count,
                attributes={"namespace": namespace, "state": state},
            )
    for cronjob in _items(snapshot.get("cronjobs")):
        attributes: dict[str, AttributeValue] = {
            "namespace": str(cronjob.get("namespace") or "default"),
            "cronjob": str(cronjob.get("cronjob") or "unknown"),
        }
        _point(
            points,
            "node_stats.kubernetes.cronjob.last_success_age",
            cronjob.get("last_successful_age_seconds"),
            unit="s",
            attributes=attributes,
        )
        _point(
            points,
            "node_stats.kubernetes.cronjob.active_jobs",
            len(cronjob.get("active_jobs", []))
            if isinstance(cronjob.get("active_jobs"), list)
            else 0,
            attributes=attributes,
        )
        _point(
            points,
            "node_stats.kubernetes.cronjob.suspended",
            1 if cronjob.get("suspended") else 0,
            attributes=attributes,
        )


def _freshness_points(points: list[MetricPoint], snapshot: Mapping[str, Any]) -> None:
    for check in _items(snapshot.get("checks")):
        attributes: dict[str, AttributeValue] = {"check": str(check.get("name") or "unknown")}
        _point(
            points,
            "node_stats.freshness.healthy",
            1 if check.get("status") == "fresh" else 0,
            attributes=attributes,
        )
        _point(
            points,
            "node_stats.freshness.age",
            check.get("age_seconds"),
            unit="s",
            attributes=attributes,
        )


def _configured_condition_points(
    points: list[MetricPoint],
    snapshot: Mapping[str, Any],
) -> None:
    for source in _items(snapshot.get("sources")):
        source_name = str(source.get("name") or "unknown")
        for item in _items(source.get("items")):
            base_attributes: dict[str, AttributeValue] = {
                "source": source_name,
                "namespace": str(item.get("namespace") or "cluster"),
                "name": str(item.get("name") or "unknown"),
            }
            conditions = _items(item.get("conditions"))
            if not conditions:
                _point(
                    points,
                    "node_stats.kubernetes.resource.condition",
                    _condition_value(item.get("ready")),
                    attributes={
                        **base_attributes,
                        "condition": str(item.get("ready_condition_type") or "Ready"),
                    },
                )
            for condition in conditions:
                _point(
                    points,
                    "node_stats.kubernetes.resource.condition",
                    _condition_value(condition.get("status")),
                    attributes={
                        **base_attributes,
                        "condition": str(condition.get("type") or "unknown"),
                    },
                )


def _root_filesystem_points(points: list[MetricPoint], snapshot: Mapping[str, Any]) -> None:
    root = _mapping(snapshot.get("root"))
    for field in (
        "total_bytes",
        "free_bytes",
        "available_bytes",
        "reserved_bytes",
        "pressure_used_bytes",
        "bytes_until_warn",
        "bytes_until_critical",
        "bytes_over_warn",
        "bytes_over_critical",
    ):
        _point(
            points,
            "node_stats.filesystem.bytes",
            root.get(field),
            unit="By",
            attributes={"field": field},
        )
    for field in ("used_percent", "inodes_used_percent"):
        _point(
            points,
            "node_stats.filesystem.utilization",
            root.get(field),
            unit="%",
            attributes={"field": field},
        )
    _point(
        points,
        "node_stats.filesystem.healthy",
        1 if root.get("status") == "ok" else 0,
    )


def _volume_points(points: list[MetricPoint], snapshot: Mapping[str, Any]) -> None:
    for namespace in _items(snapshot.get("namespaces")):
        attributes: dict[str, AttributeValue] = {
            "namespace": str(namespace.get("namespace") or "default")
        }
        _point(
            points,
            "node_stats.kubernetes.volume.used",
            namespace.get("used_bytes"),
            unit="By",
            attributes=attributes,
        )
        for field in ("volume_count", "pod_count", "truncated_volume_count"):
            _point(
                points,
                "node_stats.kubernetes.volume.namespace",
                namespace.get(field),
                attributes={**attributes, "field": field},
            )
    for volume in _items(snapshot.get("volumes")):
        attributes = {
            "namespace": str(volume.get("namespace") or "default"),
            "claim": str(volume.get("persistent_volume_claim") or "unbound"),
        }
        usage = _mapping(volume.get("usage"))
        _point(
            points,
            "node_stats.kubernetes.volume.claim.used",
            usage.get("size_bytes"),
            unit="By",
            attributes=attributes,
        )
        _point(
            points,
            "node_stats.kubernetes.volume.claim.requested",
            volume.get("requested_bytes"),
            unit="By",
            attributes=attributes,
        )
        _point(
            points,
            "node_stats.kubernetes.volume.claim.capacity",
            volume.get("capacity_bytes"),
            unit="By",
            attributes=attributes,
        )
        _point(
            points,
            "node_stats.kubernetes.volume.claim.scan_healthy",
            1 if volume.get("scan_status") == "scanned" else 0,
            attributes=attributes,
        )
        finalizers = [
            *(volume.get("pvc_finalizers") or []),
            *(volume.get("pv_finalizers") or []),
        ]
        _point(
            points,
            "node_stats.kubernetes.volume.claim.finalizers",
            len(finalizers),
            attributes=attributes,
        )
        for condition in _items(volume.get("pvc_conditions")):
            _point(
                points,
                "node_stats.kubernetes.volume.claim.condition",
                _condition_value(condition.get("status")),
                attributes={
                    **attributes,
                    "condition": str(condition.get("type") or "unknown"),
                },
            )
    _point(
        points,
        "node_stats.kubernetes.volume.unattributed_paths",
        snapshot.get("unattributed_path_count"),
    )
    unattributed_bytes = sum(
        int(_number(item.get("size_bytes")) or 0)
        for item in _items(snapshot.get("unattributed_paths"))
    )
    _point(
        points,
        "node_stats.kubernetes.volume.unattributed_used",
        unattributed_bytes,
        unit="By",
    )


def metric_points(
    snapshots: Mapping[str, Mapping[str, Any]],
    *,
    cycle_duration_seconds: float,
) -> list[MetricPoint]:
    """Map detailed snapshots to stable, low-cardinality metric series."""
    points: list[MetricPoint] = []
    _point(points, "node_stats.exporter.up", 1)
    _point(
        points,
        "node_stats.exporter.cycle.duration",
        cycle_duration_seconds,
        unit="s",
    )
    for source_name, snapshot in snapshots.items():
        attributes: dict[str, AttributeValue] = {"source": source_name}
        _point(
            points,
            "node_stats.source.up",
            0 if snapshot.get("collection_error") else 1,
            attributes=attributes,
        )
        _point(
            points,
            "node_stats.source.errors",
            _error_count(snapshot),
            attributes=attributes,
        )

    contention = snapshots.get("contention")
    if contention is not None:
        _contention_points(points, contention)
    kubelet = snapshots.get("kubelet")
    if kubelet is not None:
        _resource_usage_points(points, kubelet)
    health = snapshots.get("health")
    if health is not None:
        _health_points(points, health)
    scheduled_work = snapshots.get("scheduled_work")
    if scheduled_work is not None:
        _scheduled_work_points(points, scheduled_work)
    freshness = snapshots.get("freshness")
    if freshness is not None:
        _freshness_points(points, freshness)
    conditions = snapshots.get("conditions")
    if conditions is not None:
        _configured_condition_points(points, conditions)
    filesystem = snapshots.get("filesystem")
    if filesystem is not None:
        _root_filesystem_points(points, filesystem)
    volumes = snapshots.get("volumes")
    if volumes is not None:
        _volume_points(points, volumes)
    return points


def bounded_log_body(source: str, snapshot: Mapping[str, Any], max_bytes: int) -> str:
    """Keep source detail when it fits, otherwise emit a valid truncation envelope."""
    body = json.dumps(
        {"source": source, "snapshot": snapshot},
        separators=(",", ":"),
        sort_keys=True,
        default=str,
    )
    encoded = body.encode()
    if len(encoded) <= max_bytes:
        return body
    summary = {
        key: value
        for key, value in snapshot.items()
        if (
            key.endswith("_count")
            or key in {"source", "errors", "timed_out", "truncated", "status"}
        )
        and isinstance(value, str | int | float | bool | list | type(None))
    }
    envelope: dict[str, Any] = {
        "source": source,
        "truncated": True,
        "original_bytes": len(encoded),
        "summary": summary,
    }
    bounded = json.dumps(envelope, separators=(",", ":"), sort_keys=True, default=str)
    if len(bounded.encode()) > max_bytes:
        envelope.pop("summary")
        bounded = json.dumps(envelope, separators=(",", ":"), sort_keys=True)
    return bounded


def log_records(
    snapshots: Mapping[str, Mapping[str, Any]],
    *,
    max_log_bytes: int,
) -> list[LogRecord]:
    """Build one bounded structured log per collected source."""
    records: list[LogRecord] = []
    for source, snapshot in snapshots.items():
        errors = _error_count(snapshot)
        records.append(
            LogRecord(
                body=bounded_log_body(source, snapshot, max_log_bytes),
                attributes={
                    "node_stats.source": source,
                    "node_stats.partial": errors > 0,
                },
                severity_number=13 if errors else 9,
                severity_text="WARN" if errors else "INFO",
            )
        )
    return records


def _resource_attributes() -> dict[str, AttributeValue]:
    node_name = os.environ.get("NODE_STATS_K3S_NODE_NAME", "").strip() or socket.gethostname()
    return {
        "service.name": "node-stats-mcp",
        "service.instance.id": node_name,
        "host.name": node_name,
    }


def _bounded_metrics_body(
    points: list[MetricPoint],
    resource_attributes: dict[str, AttributeValue],
    time_unix_nano: int,
    config: ExportConfig,
) -> tuple[bytes, int, int]:
    kept = points[: config.max_metric_points]
    dropped = len(points) - len(kept)
    body = encode_request(metrics_request(kept, resource_attributes, time_unix_nano))
    while kept and len(body) > config.max_payload_bytes:
        remove_count = max(1, len(kept) // 10)
        dropped += remove_count
        del kept[-remove_count:]
        body = encode_request(metrics_request(kept, resource_attributes, time_unix_nano))
    return body, len(kept), dropped


def _bounded_logs_body(
    records: list[LogRecord],
    resource_attributes: dict[str, AttributeValue],
    time_unix_nano: int,
    config: ExportConfig,
) -> tuple[bytes, int, int]:
    kept = list(records)
    body = encode_request(logs_request(kept, resource_attributes, time_unix_nano))
    while kept and len(body) > config.max_payload_bytes:
        kept.pop()
        body = encode_request(logs_request(kept, resource_attributes, time_unix_nano))
    return body, len(kept), len(records) - len(kept)


async def _send(
    url: str,
    body: bytes,
    timeout_seconds: float,
    post: PostJson,
) -> int:
    return await asyncio.to_thread(post, url, body, timeout_seconds)


async def run_cycle(
    config: ExportConfig,
    *,
    include_volume: bool,
    dry_run: bool = False,
    post: PostJson = post_json,
    watch: NotReadyWatch | None = None,
) -> CycleResult:
    """Run one collection and independently export its metrics and source logs."""
    started = time.monotonic()
    snapshots = await collect_sources(config.limit, include_volume=include_volume)
    duration = time.monotonic() - started
    # Before the OTLP post, so a collector that is down cannot silence the alert.
    not_ready_events = 0
    conditions = snapshots.get("conditions", {})
    if watch is not None and not dry_run and "collection_error" not in conditions:
        not_ready_events = watch.observe(conditions)
    observed_at = time.time_ns()
    resource = _resource_attributes()
    points = metric_points(snapshots, cycle_duration_seconds=duration)
    records = log_records(snapshots, max_log_bytes=config.max_log_bytes)
    metrics_body, metric_count, dropped_metrics = _bounded_metrics_body(
        points,
        resource,
        observed_at,
        config,
    )
    logs_body, record_count, dropped_logs = _bounded_logs_body(
        records,
        resource,
        observed_at,
        config,
    )
    if dry_run:
        return CycleResult(
            source_count=len(snapshots),
            metric_point_count=metric_count,
            log_record_count=record_count,
            dropped_metric_points=dropped_metrics,
            dropped_log_records=dropped_logs,
            included_volume=include_volume,
            duration_seconds=duration,
            metrics_status=None,
            logs_status=None,
            errors=(),
        )

    metrics_url = signal_url(config.endpoint, "metrics")
    logs_url = signal_url(config.endpoint, "logs")
    results = await asyncio.gather(
        _send(metrics_url, metrics_body, config.timeout_seconds, post),
        _send(logs_url, logs_body, config.timeout_seconds, post),
        return_exceptions=True,
    )
    errors: list[str] = []
    statuses: list[int | None] = []
    for signal, result in zip(("metrics", "logs"), results, strict=True):
        if isinstance(result, BaseException):
            statuses.append(None)
            errors.append(f"{signal}: {type(result).__name__}: {result}"[:500])
        else:
            statuses.append(result)
            if not 200 <= result < 300:
                errors.append(f"{signal}: HTTP {result}")
    return CycleResult(
        source_count=len(snapshots),
        metric_point_count=metric_count,
        log_record_count=record_count,
        dropped_metric_points=dropped_metrics,
        dropped_log_records=dropped_logs,
        included_volume=include_volume,
        duration_seconds=duration,
        metrics_status=statuses[0],
        logs_status=statuses[1],
        errors=tuple(errors),
        not_ready_events=not_ready_events,
    )


def _report(result: CycleResult, *, dry_run: bool) -> None:
    payload = {
        "event": "node_stats_export_cycle",
        "status": "dry_run" if dry_run else "ok" if result.succeeded else "error",
        "sources": result.source_count,
        "metric_points": result.metric_point_count,
        "log_records": result.log_record_count,
        "dropped_metric_points": result.dropped_metric_points,
        "dropped_log_records": result.dropped_log_records,
        "included_volume": result.included_volume,
        "duration_seconds": round(result.duration_seconds, 3),
        "metrics_status": result.metrics_status,
        "logs_status": result.logs_status,
        "errors": result.errors,
        "not_ready_events": result.not_ready_events,
    }
    print(
        json.dumps(payload, separators=(",", ":")),
        file=sys.stdout if dry_run else sys.stderr,
        flush=True,
    )


async def run_exporter(
    config: ExportConfig,
    *,
    once: bool,
    dry_run: bool,
    post: PostJson = post_json,
) -> bool:
    """Run non-overlapping fast cycles and a slower local-volume cadence."""
    last_volume_at: float | None = None
    sender = None if dry_run else sender_from_env()
    watch = NotReadyWatch(load_notready_config(), sender) if sender else None
    if watch is None and not dry_run:
        off = {"event": "node_stats_not_ready_alerting", "status": "off", "why": "no alert DSN"}
        print(json.dumps(off), file=sys.stderr, flush=True)
    while True:
        cycle_started = time.monotonic()
        include_volume = (
            last_volume_at is None
            or cycle_started - last_volume_at >= config.volume_interval_seconds
        )
        result = await run_cycle(
            config,
            include_volume=include_volume,
            dry_run=dry_run,
            post=post,
            watch=watch,
        )
        if include_volume:
            last_volume_at = cycle_started
        _report(result, dry_run=dry_run)
        if once:
            return result.succeeded
        elapsed = time.monotonic() - cycle_started
        await asyncio.sleep(max(0.0, config.interval_seconds - elapsed))


def main() -> None:
    """CLI entrypoint for the same-image exporter sidecar."""
    init_crash_reporting("exporter")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="collect and export one cycle")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="collect one cycle, print its bounded summary, and send nothing",
    )
    args = parser.parse_args()
    try:
        config = load_config(require_endpoint=not args.dry_run)
        succeeded = asyncio.run(
            run_exporter(
                config,
                once=args.once or args.dry_run,
                dry_run=args.dry_run,
            )
        )
    except (KeyboardInterrupt, asyncio.CancelledError):
        raise SystemExit(0) from None
    except ValueError as exc:
        parser.error(str(exc))
    raise SystemExit(0 if succeeded else 1)


if __name__ == "__main__":
    main()
