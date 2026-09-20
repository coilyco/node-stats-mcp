"""FastMCP server exposing node-local host introspection over streamable-HTTP.

Read-only by construction: every tool is a read, no tool mutates the host. True
node stats (not the pod's cgroup view) rely on the deployment giving the pod
the host's namespaces - hostPID for processes, hostNetwork for net counters -
and CPU/memory come from the non-namespaced /proc/{stat,meminfo} directly. Disk
reads resolve under ROOTFS (the host root, mounted read-only at /host in the
pod). The k3s inventory tools read the Kubernetes API through a host-mounted
k3s admin kubeconfig when available, with a service-account fallback, and stay
read-only. See the deploy bundle in coilyco-bridge/deploy/services/node-stats-mcp.

File introspection is prefix-allowlisted, never arbitrary: stat_path and
read_text_head resolve the real path and refuse anything outside
NODE_STATS_READABLE_ROOTS (empty by default = file reads denied). This is the
enum-not-path discipline from the upstream node-introspection example,
generalized to a root allowlist, so the tool cannot be walked into /host/root/.ssh.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import os
import re
import ssl
import stat
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

import psutil
from mcp.server.fastmcp import FastMCP

from node_stats_mcp import storage

# Host root inside the pod. The deployment mounts the node's / read-only at
# /host and sets ROOTFS=/host. Bare local runs leave it at / (the real root).
ROOTFS = os.environ.get("ROOTFS", "/")

# Read prefixes, resolved against the symlink-collapsed path and interpreted
# inside ROOTFS. Empty denies every file read. See docs/security.md.
_READABLE_ROOTS = [r for r in os.environ.get("NODE_STATS_READABLE_ROOTS", "").split(":") if r]

# Hard cap on read_text_head so a tool call can never stream a huge file.
_MAX_READ_BYTES = int(os.environ.get("NODE_STATS_MAX_READ_BYTES", "65536"))
_K8S_TIMEOUT_SECONDS = float(os.environ.get("NODE_STATS_K8S_TIMEOUT_SECONDS", "3"))
_KUBECONFIG_PATH = os.environ.get("NODE_STATS_KUBECONFIG", "/etc/rancher/k3s/k3s.yaml")
_K3S_NODE_NAME = os.environ.get("NODE_STATS_K3S_NODE_NAME")
_FRESHNESS_CHECKS_JSON = os.environ.get("NODE_STATS_FRESHNESS_CHECKS", "[]")
_K3S_CONDITION_RESOURCES_JSON = os.environ.get("NODE_STATS_K3S_CONDITION_RESOURCES", "[]")
_DEFAULT_K3S_VOLUME_ROOTS = ("/var/lib/rancher/k3s/storage",)

# Networking sources. All procfs, so no conntrack binary and no new dependency.
_CONNTRACK_COUNT_PATH = "/proc/sys/net/netfilter/nf_conntrack_count"
_CONNTRACK_MAX_PATH = "/proc/sys/net/netfilter/nf_conntrack_max"
_CONNTRACK_STAT_PATH = "/proc/net/stat/nf_conntrack"
_EPHEMERAL_RANGE_PATH = "/proc/sys/net/ipv4/ip_local_port_range"
# Six labelled lines, constant cost. /proc/net/tcp is one line per socket and is
# longest exactly when load peaks. See docs/tools-network.md.
_SOCKSTAT_PATH = "/proc/net/sockstat"
_RESOLV_CONF_PATH = "/etc/resolv.conf"
# One veth per pod is the bulk of a k3s node's interface list and none of them
# are what an incident asks about. Overridable per deployment.
_VIRTUAL_INTERFACE_PREFIXES = tuple(
    prefix
    for prefix in os.environ.get(
        "NODE_STATS_VIRTUAL_INTERFACE_PREFIXES", "veth:cali:lxc:docker:br-"
    ).split(":")
    if prefix
)
_K3S_VOLUME_ROOTS = tuple(
    path
    for path in os.environ.get(
        "NODE_STATS_K3S_VOLUME_ROOTS", ":".join(_DEFAULT_K3S_VOLUME_ROOTS)
    ).split(":")
    if path
)
_MAX_K3S_VOLUME_PATHS = int(os.environ.get("NODE_STATS_MAX_K3S_VOLUME_PATHS", "1000"))

# Log reads are the one k3s tool that can carry a secret out of the cluster, so
# they are capped at the socket and redacted on the way out. See docs/tools-k3s.md.
_K3S_LOG_MAX_BYTES = int(os.environ.get("NODE_STATS_K3S_LOG_MAX_BYTES", "65536"))
_K3S_LOG_MAX_TAIL_LINES = int(os.environ.get("NODE_STATS_K3S_LOG_MAX_TAIL_LINES", "500"))
_K3S_LOG_DENY_NAMESPACES = tuple(
    ns for ns in os.environ.get("NODE_STATS_K3S_LOG_DENY_NAMESPACES", "").split(":") if ns
)

_DISK_WARN_PERCENT = float(os.environ.get("NODE_STATS_DISK_WARN_PERCENT", "80"))
_DISK_CRITICAL_PERCENT = float(os.environ.get("NODE_STATS_DISK_CRITICAL_PERCENT", "85"))

_DEFAULT_PRESSURE_PATHS = (
    "/home",
    "/srv",
    "/tmp",
    "/var/tmp",
    "/var/log",
    "/var/log/journal",
    "/var/lib/rancher/k3s",
    "/var/lib/rancher/k3s/agent/containerd",
    "/var/lib/kubelet",
    "/var/lib/containerd",
    "/var/lib/snapd",
)
_PRESSURE_PATHS = tuple(
    p
    for p in os.environ.get("NODE_STATS_PRESSURE_PATHS", ":".join(_DEFAULT_PRESSURE_PATHS)).split(
        ":"
    )
    if p
)
_MAX_DU_ENTRIES = int(os.environ.get("NODE_STATS_MAX_DU_ENTRIES", "200000"))
_MAX_DU_TOTAL_ENTRIES = int(os.environ.get("NODE_STATS_MAX_DU_TOTAL_ENTRIES", "200000"))
_MAX_PRESSURE_CHILDREN_PER_ROOT = int(
    os.environ.get("NODE_STATS_MAX_PRESSURE_CHILDREN_PER_ROOT", "1000")
)
_DU_TIMEOUT_SECONDS = float(os.environ.get("NODE_STATS_DU_TIMEOUT_SECONDS", "10"))

_HOST_USAGE_PROFILES_JSON = os.environ.get("NODE_STATS_HOST_USAGE_PROFILES", "")
_HOST_USAGE_MAX_ENTRIES = int(os.environ.get("NODE_STATS_HOST_USAGE_MAX_ENTRIES", "5000000"))
_HOST_USAGE_TIMEOUT_SECONDS = float(os.environ.get("NODE_STATS_HOST_USAGE_TIMEOUT_SECONDS", "900"))
_HOST_USAGE_MAX_CHILDREN = int(os.environ.get("NODE_STATS_HOST_USAGE_MAX_CHILDREN", "10000"))
_HOST_USAGE_STALE_SECONDS = int(os.environ.get("NODE_STATS_HOST_USAGE_STALE_SECONDS", "900"))
_HOST_USAGE_MAX_DEPTH = int(os.environ.get("NODE_STATS_HOST_USAGE_MAX_DEPTH", "1"))
# Depth changes reporting granularity, not the walk, but each level multiplies the
# response, so the ceiling is fixed here rather than left to profile config.
_MAX_HOST_USAGE_DEPTH = 5
_DEFAULT_HOST_USAGE_PROFILES = (
    {"name": "root", "path": "/"},
    {"name": "var", "path": "/var"},
    {"name": "var-lib", "path": "/var/lib"},
    {"name": "k3s", "path": "/var/lib/rancher/k3s"},
    # Depth 3 reaches claim -> data -> attachments, so Forgejo's managed-asset
    # split no longer needs an attended `kubectl exec` into the pod.
    {"name": "k3s-storage", "path": "/var/lib/rancher/k3s/storage", "max_depth": 3},
    {"name": "pod-ephemeral", "path": "/var/lib/kubelet/pods", "max_depth": 3},
)

_HOST_LOG_PATHS = tuple(
    path for path in os.environ.get("NODE_STATS_HOST_LOG_PATHS", "/var/log").split(":") if path
)
_JOURNAL_PATHS = tuple(
    path
    for path in os.environ.get(
        "NODE_STATS_JOURNAL_PATHS",
        "/var/log/journal:/run/log/journal",
    ).split(":")
    if path
)
_MAX_HOST_LOG_ENTRIES = int(os.environ.get("NODE_STATS_MAX_HOST_LOG_ENTRIES", "500000"))
_HOST_LOG_TIMEOUT_SECONDS = float(os.environ.get("NODE_STATS_HOST_LOG_TIMEOUT_SECONDS", "30"))
_MAX_HOST_LOG_CHILDREN = int(os.environ.get("NODE_STATS_MAX_HOST_LOG_CHILDREN", "1000"))

_MAX_DELETED_FILE_PIDS = int(os.environ.get("NODE_STATS_MAX_DELETED_FILE_PIDS", "4096"))
_MAX_DELETED_FILE_FDS = int(os.environ.get("NODE_STATS_MAX_DELETED_FILE_FDS_PER_PROCESS", "4096"))
_DELETED_FILE_TIMEOUT_SECONDS = float(
    os.environ.get("NODE_STATS_DELETED_FILE_TIMEOUT_SECONDS", "10")
)

_VMSTAT_KEYS = (
    "oom_kill",
    "pgmajfault",
    "pgscan_direct",
    "pgscan_direct_throttle",
    "pgscan_kswapd",
    "pgsteal_direct",
    "pgsteal_kswapd",
    "pswpin",
    "pswpout",
)

mcp = FastMCP(
    "node-stats",
    host=os.environ.get("HOST", "0.0.0.0"),
    port=int(os.environ.get("PORT", "8080")),
)


@dataclass(frozen=True)
class _K8sTransport:
    base_url: str
    headers: dict[str, str]
    ssl_context: ssl.SSLContext | None
    source: str


@dataclass(frozen=True)
class _K8sAuthRef:
    namespace: str | None
    pod: str | None
    container: str | None
    pod_uid: str | None
    container_id: str | None
    matched_by: str | None


@dataclass(frozen=True)
class _CgroupRefs:
    paths: list[str]
    pod_uid: str | None
    container_ids: list[str]


@dataclass
class _ScanBudget:
    """Mutable limits shared by every path in one pressure scan."""

    max_entries: int
    deadline: float
    entries_scanned: int = 0


PodContainerMatch = tuple[dict[str, Any], dict[str, Any]]
PodContainerIndex = dict[str, PodContainerMatch]
PodUidIndex = dict[str, dict[str, Any]]


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _host_path(path: str | Path) -> Path:
    raw_path = os.fspath(path)
    candidate = Path(raw_path)
    root = Path(ROOTFS)
    if raw_path.startswith("/"):
        try:
            candidate.relative_to(root)
        except ValueError:
            return root.joinpath(raw_path.lstrip("/"))
        return candidate
    if candidate.is_absolute():
        return candidate
    return root.joinpath(candidate)


def _read_host_text(path: str | Path) -> str | None:
    try:
        return _host_path(path).read_text()
    except OSError:
        return None


def _load_kubeconfig_transport() -> _K8sTransport | None:
    kubeconfig = _host_path(_KUBECONFIG_PATH)
    if not kubeconfig.exists():
        return None

    config = kubeconfig.read_text()
    server_match = re.search(r"^\s*server:\s*(\S+)\s*$", config, re.MULTILINE)
    if not server_match:
        return None
    base_url = _strip_quotes(server_match.group(1))

    def _first(pattern: str) -> str | None:
        match = re.search(pattern, config, re.MULTILINE)
        if not match:
            return None
        return _strip_quotes(match.group(1))

    ca_data = _first(r"^\s*certificate-authority-data:\s*(\S+)\s*$")
    ca_file = _first(r"^\s*certificate-authority:\s*(\S+)\s*$")
    client_cert_data = _first(r"^\s*client-certificate-data:\s*(\S+)\s*$")
    client_cert_file = _first(r"^\s*client-certificate:\s*(\S+)\s*$")
    client_key_data = _first(r"^\s*client-key-data:\s*(\S+)\s*$")
    client_key_file = _first(r"^\s*client-key:\s*(\S+)\s*$")
    token = _first(r"^\s*token:\s*(\S+)\s*$")

    ssl_context = ssl.create_default_context()
    if ca_data:
        ssl_context.load_verify_locations(cadata=base64.b64decode(ca_data).decode("utf-8"))
    elif ca_file:
        ssl_context.load_verify_locations(cafile=str(_host_path(ca_file)))

    if client_cert_data and client_key_data:
        cert_file = tempfile.NamedTemporaryFile(prefix="node-stats-k8s-cert-", delete=False)
        key_file = tempfile.NamedTemporaryFile(prefix="node-stats-k8s-key-", delete=False)
        try:
            cert_file.write(base64.b64decode(client_cert_data))
            cert_file.flush()
            key_file.write(base64.b64decode(client_key_data))
            key_file.flush()
        finally:
            cert_file.close()
            key_file.close()
        ssl_context.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)
    elif client_cert_file and client_key_file:
        ssl_context.load_cert_chain(
            certfile=str(_host_path(client_cert_file)),
            keyfile=str(_host_path(client_key_file)),
        )

    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    return _K8sTransport(
        base_url=base_url.rstrip("/"),
        headers=headers,
        ssl_context=ssl_context,
        source=str(kubeconfig),
    )


def _load_service_account_transport() -> _K8sTransport | None:
    token_path = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
    ca_path = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
    if not token_path.exists():
        return None

    host = os.environ.get("KUBERNETES_SERVICE_HOST")
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    if not host:
        return None

    headers = {"Authorization": f"Bearer {token_path.read_text().strip()}"}
    ssl_context = ssl.create_default_context()
    if ca_path.exists():
        ssl_context.load_verify_locations(cafile=str(ca_path))
    return _K8sTransport(
        base_url=f"https://{host}:{port}",
        headers=headers,
        ssl_context=ssl_context,
        source=str(token_path),
    )


def _k8s_transport() -> _K8sTransport | None:
    for loader in (_load_kubeconfig_transport, _load_service_account_transport):
        try:
            transport = loader()
        except (OSError, ValueError, binascii.Error, ssl.SSLError):
            continue
        if transport is not None:
            return transport
    return None


def _k8s_request(path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
    transport = _k8s_transport()
    if transport is None:
        raise ValueError("Kubernetes API is unavailable")
    query = f"?{urlencode(params)}" if params else ""
    req = Request(
        f"{transport.base_url}{path}{query}",
        headers={**transport.headers, "Accept": "application/json"},
    )
    with urlopen(req, timeout=_K8S_TIMEOUT_SECONDS, context=transport.ssl_context) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _k8s_list(path: str) -> tuple[list[dict[str, Any]], list[str]]:
    items: list[dict[str, Any]] = []
    errors: list[str] = []
    token: str | None = None
    while True:
        params = {"limit": "500"}
        if token:
            params["continue"] = token
        try:
            payload = _k8s_request(path, params)
        except (HTTPError, URLError, ValueError) as exc:
            errors.append(str(exc))
            break
        items.extend([item for item in payload.get("items", []) if isinstance(item, dict)])
        token = payload.get("metadata", {}).get("continue") or None
        if not token:
            break
    return items, errors


# Validated, not escaped: a selector reaches the API as a path segment.
# See docs/security.md.
_K8S_NAME_RE = re.compile(r"[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?")


def _validated_k8s_name(value: str | None, field: str) -> str | None:
    if value is None or value == "":
        return None
    text = str(value)
    if not _K8S_NAME_RE.fullmatch(text):
        raise ValueError(f"{field} must be a valid Kubernetes name")
    return text


def _k8s_namespaced_list(
    api: str, resource: str, namespace: str | None
) -> tuple[list[dict[str, Any]], list[str]]:
    """List one resource, narrowing to a namespace at the API rather than locally.

    Filtering server-side is what keeps a one-namespace question from paging the
    whole cluster back through the tool result (node-stats-mcp#7965).
    """
    checked = _validated_k8s_name(namespace, "namespace")
    if checked:
        return _k8s_list(f"{api}/namespaces/{quote(checked)}/{resource}")
    return _k8s_list(f"{api}/{resource}")


def _k8s_request_text(
    path: str, params: dict[str, str] | None = None, max_bytes: int = 65536
) -> str:
    transport = _k8s_transport()
    if transport is None:
        raise ValueError("Kubernetes API is unavailable")
    query = f"?{urlencode(params)}" if params else ""
    req = Request(
        f"{transport.base_url}{path}{query}",
        headers={**transport.headers, "Accept": "text/plain"},
    )
    with urlopen(req, timeout=_K8S_TIMEOUT_SECONDS, context=transport.ssl_context) as resp:
        # Read one byte past the cap so the caller can report truncation honestly.
        return resp.read(max_bytes + 1).decode("utf-8", errors="replace")


def _name_selected(value: Any, name: str | None, prefix: str | None) -> bool:
    if name and str(value) != name:
        return False
    if prefix and not str(value).startswith(prefix):
        return False
    return True


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _format_age(seconds: float | None) -> str | None:
    if seconds is None:
        return None
    remaining = max(0, int(seconds))
    pieces: list[str] = []
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if remaining >= size:
            count, remaining = divmod(remaining, size)
            pieces.append(f"{count}{unit}")
    if not pieces:
        pieces.append(f"{remaining}s")
    return "".join(pieces[:2])


def _parse_quantity(value: str | None) -> int | None:
    if not value:
        return None
    match = re.fullmatch(r"(?i)(\d+(?:\.\d+)?)([kmgtpe]i?|)", value.strip())
    if not match:
        return None
    number = float(match.group(1))
    suffix = match.group(2).lower()
    binary = {
        "ki": 1024,
        "mi": 1024**2,
        "gi": 1024**3,
        "ti": 1024**4,
        "pi": 1024**5,
        "ei": 1024**6,
    }
    decimal = {
        "k": 1000,
        "m": 1000**2,
        "g": 1000**3,
        "t": 1000**4,
        "p": 1000**5,
        "e": 1000**6,
    }
    if suffix in binary:
        return int(number * binary[suffix])
    if suffix in decimal:
        return int(number * decimal[suffix])
    return int(number)


def _parse_psi(text: str) -> dict[str, dict[str, float | int]]:
    pressure: dict[str, dict[str, float | int]] = {}
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        values: dict[str, float | int] = {}
        for field in fields[1:]:
            key, separator, raw_value = field.partition("=")
            if not separator:
                continue
            try:
                values[key] = int(raw_value) if key == "total" else float(raw_value)
            except ValueError:
                continue
        pressure[fields[0]] = values
    return pressure


def _node_contention(limit: int) -> dict[str, Any]:
    errors: list[str] = []
    psi: dict[str, Any] = {}
    for resource in ("cpu", "memory", "io"):
        path = f"/proc/pressure/{resource}"
        text = _read_host_text(path)
        if text is None:
            errors.append(f"{path}: unavailable")
            continue
        psi[resource] = _parse_psi(text)

    vmstat: dict[str, int] = {}
    vmstat_text = _read_host_text("/proc/vmstat")
    if vmstat_text is None:
        errors.append("/proc/vmstat: unavailable")
    else:
        for line in vmstat_text.splitlines():
            key, separator, raw_value = line.partition(" ")
            if key not in _VMSTAT_KEYS or not separator:
                continue
            try:
                vmstat[key] = int(raw_value.strip())
            except ValueError:
                continue

    devices: list[dict[str, Any]] = []
    try:
        counters = psutil.disk_io_counters(perdisk=True) or {}
    except (OSError, RuntimeError) as exc:
        counters = {}
        errors.append(f"block devices: {exc}")
    for device, counter in counters.items():
        values = counter._asdict()
        devices.append(
            {
                "device": device,
                **{
                    key: int(value)
                    for key, value in values.items()
                    if isinstance(value, int | float)
                },
            }
        )
    devices.sort(
        key=lambda entry: (
            entry.get("busy_time", 0),
            entry.get("read_bytes", 0) + entry.get("write_bytes", 0),
        ),
        reverse=True,
    )
    cap = max(1, min(limit, 100))
    return {
        "pressure_stall_information": psi,
        "vm_pressure_counters": vmstat,
        "block_devices": devices[:cap],
        "block_device_count": len(devices),
        "errors": errors,
    }


def _k3s_node() -> tuple[dict[str, Any] | None, list[str]]:
    items, errors = _k8s_list("/api/v1/nodes")
    if _K3S_NODE_NAME:
        for item in items:
            if item.get("metadata", {}).get("name") == _K3S_NODE_NAME:
                return item, errors
        errors.append(f"configured node {_K3S_NODE_NAME!r} was not returned by the API")
        return None, errors
    if len(items) == 1:
        return items[0], errors
    if not items:
        errors.append("Kubernetes API returned no nodes")
    else:
        errors.append("multiple nodes returned, set NODE_STATS_K3S_NODE_NAME")
    return None, errors


def _usage_fields(value: Any, fields: tuple[str, ...]) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    return {field: value.get(field) for field in fields if field in value}


def _normalize_kubelet_network(value: Any) -> dict[str, Any] | None:
    network = _usage_fields(value, ("time", "name", "rxBytes", "rxErrors", "txBytes", "txErrors"))
    if network is None:
        return None
    if isinstance(value.get("interfaces"), list):
        network["interfaces"] = [
            fields
            for interface in value["interfaces"][:100]
            if (
                fields := _usage_fields(
                    interface,
                    ("name", "rxBytes", "rxErrors", "txBytes", "txErrors"),
                )
            )
        ]
    return network


_CPU_USAGE_FIELDS = ("time", "usageNanoCores", "usageCoreNanoSeconds")
_MEMORY_USAGE_FIELDS = (
    "time",
    "availableBytes",
    "usageBytes",
    "workingSetBytes",
    "rssBytes",
    "pageFaults",
    "majorPageFaults",
)
_FILESYSTEM_USAGE_FIELDS = (
    "time",
    "availableBytes",
    "capacityBytes",
    "usedBytes",
    "inodesFree",
    "inodes",
    "inodesUsed",
)


def _normalize_kubelet_container(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": item.get("name"),
        "start_time": item.get("startTime"),
        "cpu": _usage_fields(item.get("cpu"), _CPU_USAGE_FIELDS),
        "memory": _usage_fields(item.get("memory"), _MEMORY_USAGE_FIELDS),
        "rootfs": _usage_fields(item.get("rootfs"), _FILESYSTEM_USAGE_FIELDS),
        "logs": _usage_fields(item.get("logs"), _FILESYSTEM_USAGE_FIELDS),
        "processes": _usage_fields(item.get("process_stats"), ("process_count",)),
    }


def _normalize_kubelet_pod(item: dict[str, Any]) -> dict[str, Any]:
    pod_ref = item.get("podRef", {})
    return {
        "namespace": pod_ref.get("namespace"),
        "pod": pod_ref.get("name"),
        "uid": pod_ref.get("uid"),
        "start_time": item.get("startTime"),
        "cpu": _usage_fields(item.get("cpu"), _CPU_USAGE_FIELDS),
        "memory": _usage_fields(item.get("memory"), _MEMORY_USAGE_FIELDS),
        "network": _normalize_kubelet_network(item.get("network")),
        "ephemeral_storage": _usage_fields(item.get("ephemeral-storage"), _FILESYSTEM_USAGE_FIELDS),
        "volumes": [
            {
                "name": volume.get("name"),
                "usage": _usage_fields(volume, _FILESYSTEM_USAGE_FIELDS),
                "pvc_ref": volume.get("pvcRef"),
            }
            for volume in item.get("volume", [])[:100]
            if isinstance(volume, dict)
        ],
        "containers": [
            _normalize_kubelet_container(container)
            for container in item.get("containers", [])[:100]
            if isinstance(container, dict)
        ],
        "processes": _usage_fields(item.get("process_stats"), ("process_count",)),
    }


def _k3s_resource_usage(limit: int) -> dict[str, Any]:
    node_item, errors = _k3s_node()
    if node_item is None:
        return {
            "source": "unavailable",
            "node": None,
            "pods": [],
            "pod_count": 0,
            "returned_pod_count": 0,
            "errors": errors,
        }
    node_name = node_item.get("metadata", {}).get("name")
    try:
        payload = _k8s_request(
            f"/api/v1/nodes/{quote(str(node_name), safe='')}/proxy/stats/summary"
        )
    except (HTTPError, URLError, ValueError) as exc:
        errors.append(f"kubelet summary: {exc}")
        return {
            "source": "unavailable",
            "node": {"name": node_name},
            "pods": [],
            "pod_count": 0,
            "returned_pod_count": 0,
            "errors": errors,
        }

    node = payload.get("node", {})
    runtime = node.get("runtime", {})
    pods = [
        _normalize_kubelet_pod(item) for item in payload.get("pods", []) if isinstance(item, dict)
    ]
    pods.sort(
        key=lambda item: (item.get("memory") or {}).get("workingSetBytes") or 0,
        reverse=True,
    )
    cap = max(1, min(limit, 100))
    return {
        "source": "kubelet-summary",
        "node": {
            "name": node.get("nodeName") or node_name,
            "start_time": node.get("startTime"),
            "cpu": _usage_fields(node.get("cpu"), _CPU_USAGE_FIELDS),
            "memory": _usage_fields(node.get("memory"), _MEMORY_USAGE_FIELDS),
            "network": _normalize_kubelet_network(node.get("network")),
            "filesystem": _usage_fields(node.get("fs"), _FILESYSTEM_USAGE_FIELDS),
            "runtime": {
                "image_filesystem": _usage_fields(runtime.get("imageFs"), _FILESYSTEM_USAGE_FIELDS),
                "container_filesystem": _usage_fields(
                    runtime.get("containerFs"), _FILESYSTEM_USAGE_FIELDS
                ),
            },
            "rlimit": _usage_fields(node.get("rlimit"), ("maxPID", "numOfRunningProcesses")),
            "system_containers": [
                _normalize_kubelet_container(container)
                for container in node.get("systemContainers", [])[:20]
                if isinstance(container, dict)
            ],
        },
        "pods": pods[:cap],
        "pod_count": len(pods),
        "returned_pod_count": min(len(pods), cap),
        "errors": errors,
    }


def _timestamp_age(value: str | None) -> dict[str, Any]:
    timestamp = _parse_timestamp(value)
    age_seconds = (datetime.now(UTC) - timestamp).total_seconds() if timestamp else None
    return {
        "timestamp": timestamp.isoformat() if timestamp else value,
        "age_seconds": int(age_seconds) if age_seconds is not None else None,
        "age": _format_age(age_seconds),
    }


def _normalize_condition(item: dict[str, Any]) -> dict[str, Any]:
    transition = _timestamp_age(item.get("lastTransitionTime"))
    return {
        "type": item.get("type"),
        "status": item.get("status"),
        "reason": item.get("reason"),
        "message": item.get("message"),
        "observed_generation": item.get("observedGeneration"),
        "last_transition_at": transition["timestamp"],
        "last_transition_age_seconds": transition["age_seconds"],
        "last_transition_age": transition["age"],
    }


def _normalize_conditions(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [_normalize_condition(item) for item in value if isinstance(item, dict)]


def _ready_condition(conditions: list[dict[str, Any]]) -> dict[str, Any] | None:
    preferred = ("ready", "healthy", "available", "synced", "reconciled")
    by_type = {str(condition.get("type", "")).lower(): condition for condition in conditions}
    for condition_type in preferred:
        if condition_type in by_type:
            return by_type[condition_type]
    return None


def _normalize_node_health(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get("metadata", {})
    spec = item.get("spec", {})
    status = item.get("status", {})
    created = _timestamp_age(metadata.get("creationTimestamp"))
    return {
        "name": metadata.get("name"),
        "created_at": created["timestamp"],
        "age_seconds": created["age_seconds"],
        "age": created["age"],
        "unschedulable": bool(spec.get("unschedulable")),
        "taints": [
            {
                "key": taint.get("key"),
                "value": taint.get("value"),
                "effect": taint.get("effect"),
                "time_added": taint.get("timeAdded"),
            }
            for taint in spec.get("taints", [])
            if isinstance(taint, dict)
        ],
        "capacity": status.get("capacity", {}),
        "allocatable": status.get("allocatable", {}),
        "addresses": [
            {"type": address.get("type"), "address": address.get("address")}
            for address in status.get("addresses", [])
            if isinstance(address, dict)
        ],
        "conditions": _normalize_conditions(status.get("conditions")),
    }


def _event_observed_at(item: dict[str, Any]) -> str | None:
    series = item.get("series", {})
    metadata = item.get("metadata", {})
    return (
        item.get("eventTime")
        or series.get("lastObservedTime")
        or item.get("lastTimestamp")
        or item.get("firstTimestamp")
        or metadata.get("creationTimestamp")
    )


def _normalize_event(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get("metadata", {})
    involved = item.get("involvedObject", {})
    source = item.get("source", {})
    observed = _timestamp_age(_event_observed_at(item))
    series = item.get("series", {})
    return {
        "namespace": metadata.get("namespace"),
        "type": item.get("type"),
        "reason": item.get("reason"),
        "message": item.get("message") or item.get("note"),
        "count": series.get("count") or item.get("count"),
        "object": {
            "kind": involved.get("kind"),
            "namespace": involved.get("namespace") or metadata.get("namespace"),
            "name": involved.get("name"),
        },
        "source": (
            item.get("reportingController")
            or source.get("component")
            or item.get("reportingInstance")
        ),
        "observed_at": observed["timestamp"],
        "age_seconds": observed["age_seconds"],
        "age": observed["age"],
    }


def _event_relevant_to_node(
    item: dict[str, Any],
    node_name: str,
    pod_names: set[tuple[str, str]],
    pod_uids: set[str],
) -> bool:
    involved = item.get("involvedObject", {})
    kind = involved.get("kind")
    if kind == "Node":
        return involved.get("name") == node_name
    if kind == "Pod":
        namespace = involved.get("namespace") or item.get("metadata", {}).get("namespace")
        return (str(namespace), str(involved.get("name"))) in pod_names or str(
            involved.get("uid")
        ) in pod_uids
    return item.get("type") == "Warning"


def _k3s_node_health(limit: int, max_age_hours: int) -> dict[str, Any]:
    node_item, errors = _k3s_node()
    if node_item is None:
        return {
            "node": None,
            "events": [],
            "event_count": 0,
            "returned_event_count": 0,
            "errors": errors,
        }
    node_name = str(node_item.get("metadata", {}).get("name"))
    pod_items, pod_errors = _k8s_list("/api/v1/pods")
    event_items, event_errors = _k8s_list("/api/v1/events")
    errors.extend(f"pods: {error}" for error in pod_errors)
    errors.extend(f"events: {error}" for error in event_errors)
    node_pods = [item for item in pod_items if item.get("spec", {}).get("nodeName") == node_name]
    pod_names = {
        (
            str(item.get("metadata", {}).get("namespace")),
            str(item.get("metadata", {}).get("name")),
        )
        for item in node_pods
    }
    pod_uids = {
        str(item.get("metadata", {}).get("uid"))
        for item in node_pods
        if item.get("metadata", {}).get("uid")
    }
    maximum_age_seconds = max(1, min(max_age_hours, 168)) * 3600
    events: list[dict[str, Any]] = []
    for item in event_items:
        if not _event_relevant_to_node(item, node_name, pod_names, pod_uids):
            continue
        event = _normalize_event(item)
        event_age = event.get("age_seconds")
        if event_age is not None and event_age > maximum_age_seconds:
            continue
        events.append(event)
    events.sort(
        key=lambda event: (
            event.get("age_seconds") is None,
            event.get("age_seconds") or 0,
        )
    )
    cap = max(1, min(limit, 100))
    return {
        "node": _normalize_node_health(node_item),
        "events": events[:cap],
        "event_count": len(events),
        "returned_event_count": min(len(events), cap),
        "max_age_hours": max(1, min(max_age_hours, 168)),
        "errors": errors,
    }


def _normalize_job(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get("metadata", {})
    spec = item.get("spec", {})
    status = item.get("status", {})
    created = _timestamp_age(metadata.get("creationTimestamp"))
    started = _timestamp_age(status.get("startTime"))
    completed = _timestamp_age(status.get("completionTime"))
    start_time = _parse_timestamp(status.get("startTime"))
    completion_time = _parse_timestamp(status.get("completionTime"))
    duration_seconds = (
        int((completion_time - start_time).total_seconds())
        if start_time and completion_time
        else None
    )
    owner = next(
        (
            ref
            for ref in metadata.get("ownerReferences", [])
            if isinstance(ref, dict) and ref.get("kind") == "CronJob"
        ),
        None,
    )
    return {
        "namespace": metadata.get("namespace"),
        "job": metadata.get("name"),
        "cronjob": owner.get("name") if owner else None,
        "created_at": created["timestamp"],
        "age_seconds": created["age_seconds"],
        "age": created["age"],
        "start_at": started["timestamp"],
        "start_age_seconds": started["age_seconds"],
        "completion_at": completed["timestamp"],
        "completion_age_seconds": completed["age_seconds"],
        "duration_seconds": duration_seconds,
        "active": int(status.get("active") or 0),
        "succeeded": int(status.get("succeeded") or 0),
        "failed": int(status.get("failed") or 0),
        "ready": status.get("ready"),
        "completions": spec.get("completions"),
        "parallelism": spec.get("parallelism"),
        "backoff_limit": spec.get("backoffLimit"),
        "suspended": bool(spec.get("suspend")),
        "conditions": _normalize_conditions(status.get("conditions")),
    }


def _normalize_cronjob(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get("metadata", {})
    spec = item.get("spec", {})
    status = item.get("status", {})
    created = _timestamp_age(metadata.get("creationTimestamp"))
    scheduled = _timestamp_age(status.get("lastScheduleTime"))
    successful = _timestamp_age(status.get("lastSuccessfulTime"))
    return {
        "namespace": metadata.get("namespace"),
        "cronjob": metadata.get("name"),
        "schedule": spec.get("schedule"),
        "time_zone": spec.get("timeZone"),
        "suspended": bool(spec.get("suspend")),
        "concurrency_policy": spec.get("concurrencyPolicy"),
        "created_at": created["timestamp"],
        "age_seconds": created["age_seconds"],
        "age": created["age"],
        "last_schedule_at": scheduled["timestamp"],
        "last_schedule_age_seconds": scheduled["age_seconds"],
        "last_schedule_age": scheduled["age"],
        "last_successful_at": successful["timestamp"],
        "last_successful_age_seconds": successful["age_seconds"],
        "last_successful_age": successful["age"],
        "active_jobs": [
            {"namespace": ref.get("namespace"), "name": ref.get("name")}
            for ref in status.get("active", [])[:100]
            if isinstance(ref, dict)
        ],
    }


def _k3s_scheduled_work(limit: int) -> dict[str, Any]:
    job_items, job_errors = _k8s_list("/apis/batch/v1/jobs")
    cronjob_items, cronjob_errors = _k8s_list("/apis/batch/v1/cronjobs")
    jobs = [_normalize_job(item) for item in job_items]
    cronjobs = [_normalize_cronjob(item) for item in cronjob_items]
    jobs.sort(
        key=lambda job: (
            job["failed"] > 0,
            job["active"] > 0,
            -(job.get("start_age_seconds") or 0),
        ),
        reverse=True,
    )
    cronjobs.sort(
        key=lambda cronjob: (
            cronjob["suspended"],
            cronjob.get("last_successful_age_seconds") or -1,
        ),
        reverse=True,
    )
    cap = max(1, min(limit, 100))
    return {
        "jobs": jobs[:cap],
        "job_count": len(jobs),
        "returned_job_count": min(len(jobs), cap),
        "cronjobs": cronjobs[:cap],
        "cronjob_count": len(cronjobs),
        "returned_cronjob_count": min(len(cronjobs), cap),
        "errors": [
            *(f"jobs: {error}" for error in job_errors),
            *(f"cronjobs: {error}" for error in cronjob_errors),
        ],
    }


def _configured_objects(raw_value: str, setting: str) -> tuple[list[dict[str, Any]], list[str]]:
    try:
        value = json.loads(raw_value)
    except json.JSONDecodeError as exc:
        return [], [f"{setting}: invalid JSON: {exc.msg}"]
    if not isinstance(value, list):
        return [], [f"{setting}: expected a JSON list"]
    objects: list[dict[str, Any]] = []
    errors: list[str] = []
    for index, item in enumerate(value):
        if isinstance(item, dict):
            objects.append(item)
        else:
            errors.append(f"{setting}[{index}]: expected an object")
    return objects, errors


_CONFIG_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_K8S_API_TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,252}$")


def _positive_number(
    config: dict[str, Any],
    key: str,
    default: int | float,
    errors: list[str],
    profile_name: str,
) -> int | float:
    value = config.get(key, default)
    if not isinstance(value, int | float) or isinstance(value, bool) or value <= 0:
        errors.append(f"host usage profile {profile_name!r}: {key} must be positive")
        return default
    return value


def _host_usage_profiles() -> tuple[list[storage.UsageProfile], list[str]]:
    if _HOST_USAGE_PROFILES_JSON.strip():
        configs, errors = _configured_objects(
            _HOST_USAGE_PROFILES_JSON,
            "NODE_STATS_HOST_USAGE_PROFILES",
        )
    else:
        configs = [dict(config) for config in _DEFAULT_HOST_USAGE_PROFILES]
        errors = []
    root = Path(ROOTFS).resolve()
    profiles: list[storage.UsageProfile] = []
    names: set[str] = set()
    for index, config in enumerate(configs):
        name = config.get("name")
        path = config.get("path")
        if not isinstance(name, str) or not _CONFIG_NAME_RE.fullmatch(name):
            errors.append(f"host usage profile {index}: invalid name")
            continue
        if name in names:
            errors.append(f"host usage profile {name!r}: duplicate name")
            continue
        if not isinstance(path, str) or not path.startswith("/"):
            errors.append(f"host usage profile {name!r}: path must be absolute")
            continue
        target = _host_path(path).resolve()
        if target != root and root not in target.parents:
            errors.append(f"host usage profile {name!r}: configured path escapes ROOTFS")
            continue
        raw_excludes = config.get("exclude_paths", [])
        if not isinstance(raw_excludes, list) or not all(
            isinstance(exclude, str) and exclude.startswith("/") for exclude in raw_excludes
        ):
            errors.append(
                f"host usage profile {name!r}: exclude_paths must be absolute path strings"
            )
            continue
        exclude_paths = []
        invalid_exclude = False
        for exclude in raw_excludes:
            excluded = _host_path(exclude).resolve()
            if excluded != target and target not in excluded.parents:
                errors.append(
                    f"host usage profile {name!r}: exclusion {exclude!r} is outside the profile"
                )
                invalid_exclude = True
                break
            exclude_paths.append(exclude)
        if invalid_exclude:
            continue
        stale_after = _positive_number(
            config,
            "stale_after_seconds",
            _HOST_USAGE_STALE_SECONDS,
            errors,
            name,
        )
        max_entries = _positive_number(
            config,
            "max_entries",
            _HOST_USAGE_MAX_ENTRIES,
            errors,
            name,
        )
        timeout = _positive_number(
            config,
            "timeout_seconds",
            _HOST_USAGE_TIMEOUT_SECONDS,
            errors,
            name,
        )
        max_children = _positive_number(
            config,
            "max_children",
            _HOST_USAGE_MAX_CHILDREN,
            errors,
            name,
        )
        max_depth = min(
            _MAX_HOST_USAGE_DEPTH,
            int(_positive_number(config, "max_depth", _HOST_USAGE_MAX_DEPTH, errors, name)),
        )
        profiles.append(
            storage.UsageProfile(
                name=name,
                path=path,
                exclude_paths=tuple(exclude_paths),
                stale_after_seconds=int(stale_after),
                max_entries=int(max_entries),
                timeout_seconds=float(timeout),
                max_children=int(max_children),
                max_depth=max_depth,
            )
        )
        names.add(name)
    return profiles, errors


def _validated_host_paths(
    configured_paths: tuple[str, ...],
    setting: str,
) -> tuple[tuple[str, ...], list[str]]:
    root = Path(ROOTFS).resolve()
    paths: list[str] = []
    errors: list[str] = []
    for index, path in enumerate(configured_paths):
        if not path.startswith("/"):
            errors.append(f"{setting}[{index}]: path must be absolute")
            continue
        target = _host_path(path).resolve()
        if target != root and root not in target.parents:
            errors.append(f"{setting}[{index}]: configured path escapes ROOTFS")
            continue
        if path not in paths:
            paths.append(path)
    return tuple(paths), errors


_HOST_USAGE_PROFILES, _HOST_USAGE_PROFILE_ERRORS = _host_usage_profiles()
_HOST_USAGE_SNAPSHOTS = storage.HostUsageSnapshots(ROOTFS, _HOST_USAGE_PROFILES)
_HOST_LOG_PATHS, _HOST_LOG_PATH_ERRORS = _validated_host_paths(
    _HOST_LOG_PATHS,
    "NODE_STATS_HOST_LOG_PATHS",
)
_JOURNAL_PATHS, _JOURNAL_PATH_ERRORS = _validated_host_paths(
    _JOURNAL_PATHS,
    "NODE_STATS_JOURNAL_PATHS",
)
_HOST_LOG_CONFIGURATION_ERRORS = [*_HOST_LOG_PATH_ERRORS, *_JOURNAL_PATH_ERRORS]


def _configured_freshness() -> dict[str, Any]:
    configs, errors = _configured_objects(_FRESHNESS_CHECKS_JSON, "NODE_STATS_FRESHNESS_CHECKS")
    root = Path(ROOTFS).resolve()
    now = time.time()
    checks: list[dict[str, Any]] = []
    for index, config in enumerate(configs):
        name = config.get("name")
        path = config.get("path")
        max_age = config.get("max_age_seconds")
        if not isinstance(name, str) or not _CONFIG_NAME_RE.fullmatch(name):
            errors.append(f"freshness check {index}: invalid name")
            continue
        if not isinstance(path, str) or not path.startswith("/"):
            errors.append(f"freshness check {name!r}: path must be absolute")
            continue
        if not isinstance(max_age, int | float) or max_age <= 0:
            errors.append(f"freshness check {name!r}: max_age_seconds must be positive")
            continue
        target = _host_path(path).resolve()
        if target != root and root not in target.parents:
            errors.append(f"freshness check {name!r}: configured path escapes ROOTFS")
            continue
        check: dict[str, Any] = {
            "name": name,
            "path": path,
            "max_age_seconds": int(max_age),
        }
        try:
            path_stat = target.stat()
        except FileNotFoundError:
            check.update(
                {
                    "exists": False,
                    "status": "missing",
                    "mtime_epoch": None,
                    "age_seconds": None,
                    "age": None,
                    "is_file": False,
                    "is_dir": False,
                    "size_bytes": None,
                }
            )
        except OSError as exc:
            check.update({"exists": None, "status": "error", "error": str(exc)})
        else:
            age_seconds = int(now - path_stat.st_mtime)
            status = (
                "clock_skew"
                if age_seconds < -300
                else "stale"
                if age_seconds > max_age
                else "fresh"
            )
            check.update(
                {
                    "exists": True,
                    "status": status,
                    "mtime_epoch": path_stat.st_mtime,
                    "age_seconds": age_seconds,
                    "age": _format_age(age_seconds),
                    "is_file": stat.S_ISREG(path_stat.st_mode),
                    "is_dir": stat.S_ISDIR(path_stat.st_mode),
                    "size_bytes": path_stat.st_size,
                }
            )
        checks.append(check)
    return {"checks": checks, "configured_check_count": len(configs), "errors": errors}


def _condition_resource_path(config: dict[str, Any]) -> tuple[str | None, str | None]:
    group = config.get("group")
    version = config.get("version")
    resource = config.get("resource")
    namespace = config.get("namespace")
    tokens = {
        "group": group,
        "version": version,
        "resource": resource,
    }
    for field, value in tokens.items():
        if not isinstance(value, str) or not _K8S_API_TOKEN_RE.fullmatch(value):
            return None, f"invalid {field}"
    if namespace is not None and (
        not isinstance(namespace, str) or not _K8S_API_TOKEN_RE.fullmatch(namespace)
    ):
        return None, "invalid namespace"
    assert isinstance(group, str)
    assert isinstance(version, str)
    assert isinstance(resource, str)
    base = f"/apis/{quote(group, safe='.')}/{quote(version, safe='')}"
    if namespace:
        base += f"/namespaces/{quote(namespace, safe='')}"
    return f"{base}/{quote(resource, safe='')}", None


def _normalize_condition_resource_item(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get("metadata", {})
    status = item.get("status", {})
    created = _timestamp_age(metadata.get("creationTimestamp"))
    conditions = _normalize_conditions(status.get("conditions"))
    ready = _ready_condition(conditions)
    return {
        "namespace": metadata.get("namespace"),
        "name": metadata.get("name"),
        "generation": metadata.get("generation"),
        "observed_generation": status.get("observedGeneration"),
        "deletion_timestamp": metadata.get("deletionTimestamp"),
        "created_at": created["timestamp"],
        "age_seconds": created["age_seconds"],
        "age": created["age"],
        "ready": ready.get("status") if ready else None,
        "ready_condition_type": ready.get("type") if ready else None,
        "conditions": conditions,
    }


def _k3s_configured_conditions(
    limit_per_source: int,
    namespace: str | None = None,
    name: str | None = None,
    source: str | None = None,
) -> dict[str, Any]:
    configs, errors = _configured_objects(
        _K3S_CONDITION_RESOURCES_JSON,
        "NODE_STATS_K3S_CONDITION_RESOURCES",
    )
    cap = max(1, min(limit_per_source, 100))
    selected_name = _validated_k8s_name(name, "name")
    _validated_k8s_name(namespace, "namespace")
    sources: list[dict[str, Any]] = []
    for index, config in enumerate(configs):
        name = config.get("name")
        if not isinstance(name, str) or not _CONFIG_NAME_RE.fullmatch(name):
            errors.append(f"condition resource {index}: invalid name")
            continue
        path, path_error = _condition_resource_path(config)
        if path_error:
            errors.append(f"condition resource {name!r}: {path_error}")
            continue
        # `name` is the configured source name here, not the object selector.
        if source and source.lower() != name.lower():
            continue
        items, source_errors = _k8s_list(str(path))
        normalized = [_normalize_condition_resource_item(item) for item in items]
        if namespace:
            normalized = [i for i in normalized if i.get("namespace") == namespace]
        if selected_name:
            normalized = [i for i in normalized if i.get("name") == selected_name]
        normalized.sort(
            key=lambda item: (
                item["ready"] not in ("True", True),
                item.get("age_seconds") or 0,
            ),
            reverse=True,
        )
        sources.append(
            {
                "name": name,
                "group": config["group"],
                "version": config["version"],
                "resource": config["resource"],
                "namespace": config.get("namespace"),
                "items": normalized[:cap],
                "item_count": len(normalized),
                "returned_item_count": min(len(normalized), cap),
                "errors": source_errors,
            }
        )
    return {
        "sources": sources,
        "configured_source_count": len(configs),
        "errors": errors,
    }


_WORKLOAD_KINDS: dict[str, tuple[str, str, str]] = {
    "deployment": ("/apis/apps/v1", "deployments", "Deployment"),
    "statefulset": ("/apis/apps/v1", "statefulsets", "StatefulSet"),
    "daemonset": ("/apis/apps/v1", "daemonsets", "DaemonSet"),
}

_NETWORK_KINDS: dict[str, tuple[str, str, str]] = {
    "service": ("/api/v1", "services", "Service"),
    "ingress": ("/apis/networking.k8s.io/v1", "ingresses", "Ingress"),
    "endpointslice": ("/apis/discovery.k8s.io/v1", "endpointslices", "EndpointSlice"),
}

# Backstop only, and the deny list is the control that binds.
# See docs/security.md.
_LOG_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)((?:--?)?(?:user[_-]?token|api[_-]?key|access[_-]?key|password|passwd"
    r"|secret|token|authorization|bearer)[\"']?\s*[=:]\s*[\"']?)([^\s\"',;)]{4,})"
)
_LOG_SECRET_LITERAL_RES = (
    re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}"),
    re.compile(r"\b(?:gh[pousr]|xox[baprs])_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)


def _redact_log_text(text: str) -> tuple[str, int]:
    redactions = 0

    def _assignment(match: re.Match[str]) -> str:
        nonlocal redactions
        redactions += 1
        return f"{match.group(1)}<REDACTED>"

    redacted = _LOG_SECRET_ASSIGNMENT_RE.sub(_assignment, text)
    for pattern in _LOG_SECRET_LITERAL_RES:
        redacted, count = pattern.subn("<REDACTED>", redacted)
        redactions += count
    return redacted, redactions


def _k3s_pods(
    namespace: str | None, name: str | None, name_prefix: str | None, limit: int
) -> dict[str, Any]:
    items, errors = _k8s_namespaced_list("/api/v1", "pods", namespace)
    pods = [_normalize_pod_for_index(item) for item in items]
    selected = [pod for pod in pods if _name_selected(pod.get("pod"), name, name_prefix)]
    # Unhealthy first: a caller narrowing to a namespace is looking for the
    # broken one, and a cap that truncates past it answers the wrong question.
    selected.sort(key=lambda pod: (pod.get("phase") == "Running", pod.get("pod") or ""))
    cap = max(1, min(limit, 500))
    return {
        "namespace": namespace,
        "pods": selected[:cap],
        "pod_count": len(selected),
        "returned_pod_count": min(len(selected), cap),
        "errors": errors,
    }


def _normalize_workload(item: dict[str, Any], kind: str) -> dict[str, Any]:
    metadata = item.get("metadata", {})
    spec = item.get("spec", {})
    status = item.get("status", {})
    template = spec.get("template", {})
    template_spec = template.get("spec", {}) if isinstance(template, dict) else {}
    created = _timestamp_age(metadata.get("creationTimestamp"))
    images = [
        {"container": container.get("name"), "image": container.get("image")}
        for container in template_spec.get("containers", [])
        if isinstance(container, dict)
    ]
    if kind == "DaemonSet":
        desired = status.get("desiredNumberScheduled")
        ready = status.get("numberReady")
        updated = status.get("updatedNumberScheduled")
        available = status.get("numberAvailable")
    else:
        desired = spec.get("replicas")
        ready = status.get("readyReplicas")
        updated = status.get("updatedReplicas")
        available = status.get("availableReplicas")
    generation = metadata.get("generation")
    observed = status.get("observedGeneration")
    rollout_complete: bool | None = None
    if desired is not None:
        rollout_complete = (
            (ready or 0) == desired
            and (updated or 0) == desired
            and (generation is None or observed == generation)
        )
    return {
        "kind": kind,
        "namespace": metadata.get("namespace"),
        "name": metadata.get("name"),
        "created_at": created["timestamp"],
        "age_seconds": created["age_seconds"],
        "age": created["age"],
        "generation": generation,
        "observed_generation": observed,
        # The spec image, not the running pod image. They differ exactly when a
        # rollout was applied and has not landed, which is the question asked.
        "spec_images": images,
        "desired_replicas": desired,
        "ready_replicas": ready,
        "updated_replicas": updated,
        "available_replicas": available,
        "rollout_complete": rollout_complete,
        "conditions": _normalize_conditions(status.get("conditions")),
    }


def _k3s_workloads(
    namespace: str | None, name: str | None, kind: str | None, limit: int
) -> dict[str, Any]:
    if kind is not None and kind.lower() not in _WORKLOAD_KINDS:
        raise ValueError(f"kind must be one of {', '.join(sorted(_WORKLOAD_KINDS))}")
    wanted = [kind.lower()] if kind else sorted(_WORKLOAD_KINDS)
    workloads: list[dict[str, Any]] = []
    errors: list[str] = []
    for key in wanted:
        api, resource, display = _WORKLOAD_KINDS[key]
        items, kind_errors = _k8s_namespaced_list(api, resource, namespace)
        errors.extend(kind_errors)
        workloads.extend(
            _normalize_workload(item, display)
            for item in items
            if _name_selected(item.get("metadata", {}).get("name"), name, None)
        )
    workloads.sort(key=lambda w: (w.get("rollout_complete") is not False, w.get("name") or ""))
    cap = max(1, min(limit, 300))
    return {
        "namespace": namespace,
        "workloads": workloads[:cap],
        "workload_count": len(workloads),
        "returned_workload_count": min(len(workloads), cap),
        "errors": errors,
    }


def _normalize_persistent_volume(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get("metadata", {})
    spec = item.get("spec", {})
    status = item.get("status", {})
    claim_ref = spec.get("claimRef", {})
    return {
        "persistent_volume": metadata.get("name"),
        "phase": status.get("phase"),
        "reason": status.get("reason"),
        "message": status.get("message"),
        "storage_class": spec.get("storageClassName"),
        "reclaim_policy": spec.get("persistentVolumeReclaimPolicy"),
        "capacity_bytes": _parse_quantity(spec.get("capacity", {}).get("storage")),
        "deletion_timestamp": metadata.get("deletionTimestamp"),
        "claim": {
            "namespace": claim_ref.get("namespace"),
            "name": claim_ref.get("name"),
        },
    }


def _k3s_storage_claims(namespace: str | None, name: str | None, limit: int) -> dict[str, Any]:
    pvc_items, errors = _k8s_namespaced_list("/api/v1", "persistentvolumeclaims", namespace)
    pv_items, pv_errors = _k8s_list("/api/v1/persistentvolumes")
    errors.extend(pv_errors)
    volumes = {
        item.get("metadata", {}).get("name"): _normalize_persistent_volume(item)
        for item in pv_items
    }
    claims: list[dict[str, Any]] = []
    for item in pvc_items:
        if not _name_selected(item.get("metadata", {}).get("name"), name, None):
            continue
        claim = _normalize_pvc(item)
        claim["persistent_volume_detail"] = volumes.get(claim.get("persistent_volume"))
        claims.append(claim)
    claims.sort(key=lambda c: (c.get("phase") == "Bound", c.get("persistent_volume_claim") or ""))
    cap = max(1, min(limit, 300))
    return {
        "namespace": namespace,
        "claims": claims[:cap],
        "claim_count": len(claims),
        "returned_claim_count": min(len(claims), cap),
        "errors": errors,
    }


def _k3s_events(
    namespace: str | None,
    kind: str | None,
    name: str | None,
    limit: int,
    max_age_hours: int,
) -> dict[str, Any]:
    items, errors = _k8s_namespaced_list("/api/v1", "events", namespace)
    events = [_normalize_event(item) for item in items]
    cutoff = max(1, max_age_hours) * 3600
    selected = []
    for event in events:
        age = event.get("age_seconds")
        if age is not None and age > cutoff:
            continue
        involved = event.get("object", {})
        if kind and str(involved.get("kind", "")).lower() != kind.lower():
            continue
        if name and not _name_selected(involved.get("name"), name, None):
            continue
        selected.append(event)
    # Warnings first, then newest: the ordering a reader wants when an object
    # has fifty Normal events and one Warning that explains the incident.
    selected.sort(key=lambda e: (e.get("type") != "Warning", e.get("age_seconds") or 0))
    cap = max(1, min(limit, 200))
    return {
        "namespace": namespace,
        "events": selected[:cap],
        "event_count": len(selected),
        "returned_event_count": min(len(selected), cap),
        "max_age_hours": max_age_hours,
        "errors": errors,
    }


def _k3s_namespaces(limit: int) -> dict[str, Any]:
    items, errors = _k8s_list("/api/v1/namespaces")
    namespaces = []
    for item in items:
        metadata = item.get("metadata", {})
        created = _timestamp_age(metadata.get("creationTimestamp"))
        namespaces.append(
            {
                "namespace": metadata.get("name"),
                "phase": item.get("status", {}).get("phase"),
                "created_at": created["timestamp"],
                "age_seconds": created["age_seconds"],
                "age": created["age"],
                "deletion_timestamp": metadata.get("deletionTimestamp"),
                "finalizers": (metadata.get("finalizers") or [])[:20],
            }
        )
    namespaces.sort(key=lambda n: n.get("namespace") or "")
    cap = max(1, min(limit, 500))
    return {
        "namespaces": namespaces[:cap],
        "namespace_count": len(namespaces),
        "returned_namespace_count": min(len(namespaces), cap),
        "errors": errors,
    }


def _normalize_network_object(item: dict[str, Any], kind: str) -> dict[str, Any]:
    metadata = item.get("metadata", {})
    spec = item.get("spec", {})
    normalized: dict[str, Any] = {
        "kind": kind,
        "namespace": metadata.get("namespace"),
        "name": metadata.get("name"),
    }
    if kind == "Service":
        normalized["type"] = spec.get("type")
        normalized["cluster_ip"] = spec.get("clusterIP")
        normalized["selector"] = spec.get("selector")
        normalized["ports"] = [
            {
                "name": port.get("name"),
                "port": port.get("port"),
                "target_port": port.get("targetPort"),
                "node_port": port.get("nodePort"),
                "protocol": port.get("protocol"),
            }
            for port in spec.get("ports", [])
            if isinstance(port, dict)
        ][:50]
    elif kind == "Ingress":
        normalized["ingress_class"] = spec.get("ingressClassName")
        normalized["hosts"] = [
            rule.get("host") for rule in spec.get("rules", []) if isinstance(rule, dict)
        ][:50]
        normalized["tls_secrets"] = [
            tls.get("secretName") for tls in spec.get("tls", []) if isinstance(tls, dict)
        ][:50]
    else:
        # An EndpointSlice with no ready address is the shape of a Service that
        # resolves and answers nothing, which a Service read alone cannot show.
        endpoints = item.get("endpoints", []) or []
        ready = sum(
            1
            for endpoint in endpoints
            if isinstance(endpoint, dict) and endpoint.get("conditions", {}).get("ready")
        )
        normalized["service"] = metadata.get("labels", {}).get("kubernetes.io/service-name")
        normalized["endpoint_count"] = len(endpoints)
        normalized["ready_endpoint_count"] = ready
        normalized["ports"] = [
            {"name": port.get("name"), "port": port.get("port")}
            for port in item.get("ports", []) or []
            if isinstance(port, dict)
        ][:50]
    return normalized


def _k3s_network(namespace: str | None, name: str | None, limit: int) -> dict[str, Any]:
    objects: list[dict[str, Any]] = []
    errors: list[str] = []
    for key in sorted(_NETWORK_KINDS):
        api, resource, display = _NETWORK_KINDS[key]
        items, kind_errors = _k8s_namespaced_list(api, resource, namespace)
        errors.extend(kind_errors)
        for item in items:
            candidate = item.get("metadata", {}).get("name")
            service_label = (
                item.get("metadata", {}).get("labels", {}).get("kubernetes.io/service-name")
            )
            if name and not (_name_selected(candidate, None, name) or service_label == name):
                continue
            objects.append(_normalize_network_object(item, display))
    cap = max(1, min(limit, 300))
    return {
        "namespace": namespace,
        "objects": objects[:cap],
        "object_count": len(objects),
        "returned_object_count": min(len(objects), cap),
        "errors": errors,
    }


def _k3s_logs(
    namespace: str,
    pod: str,
    container: str | None,
    tail_lines: int,
    previous: bool,
) -> dict[str, Any]:
    checked_namespace = _validated_k8s_name(namespace, "namespace")
    checked_pod = _validated_k8s_name(pod, "pod")
    checked_container = _validated_k8s_name(container, "container")
    if not checked_namespace or not checked_pod:
        raise ValueError("namespace and pod are required")
    if checked_namespace in _K3S_LOG_DENY_NAMESPACES:
        raise ValueError(f"namespace {checked_namespace!r} is denied for log reads")
    tail = max(1, min(tail_lines, _K3S_LOG_MAX_TAIL_LINES))
    params = {"tailLines": str(tail), "timestamps": "true"}
    if checked_container:
        params["container"] = checked_container
    if previous:
        params["previous"] = "true"
    path = f"/api/v1/namespaces/{quote(checked_namespace)}/pods/{quote(checked_pod)}/log"
    errors: list[str] = []
    try:
        raw = _k8s_request_text(path, params, _K3S_LOG_MAX_BYTES)
    except (HTTPError, URLError, ValueError) as exc:
        return {
            "namespace": checked_namespace,
            "pod": checked_pod,
            "container": checked_container,
            "previous": previous,
            "lines": [],
            "errors": [str(exc)],
        }
    truncated = len(raw.encode("utf-8", errors="replace")) > _K3S_LOG_MAX_BYTES
    if truncated:
        raw = raw[:_K3S_LOG_MAX_BYTES]
        # A partial first line is worse than no first line, so drop it.
        raw = raw.split("\n", 1)[1] if "\n" in raw else ""
    redacted, redactions = _redact_log_text(raw)
    lines = [line for line in redacted.splitlines() if line]
    return {
        "namespace": checked_namespace,
        "pod": checked_pod,
        "container": checked_container,
        "previous": previous,
        "tail_lines": tail,
        "truncated": truncated,
        "redaction_count": redactions,
        "lines": lines,
        "errors": errors,
    }


def _normalize_container_id(container_id: str | None) -> str | None:
    if not container_id:
        return None
    value = container_id.strip()
    if "://" in value:
        value = value.split("://", 1)[1]
    return value or None


_POD_UID_RE = re.compile(
    r"pod(?P<uid>[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})",
    re.IGNORECASE,
)
_CONTAINER_ID_RE = re.compile(
    r"(?:containerd|cri-containerd|cri-o|crio|docker)[-:/](?P<id>[0-9a-f]{12,64})(?:\.scope)?",
    re.IGNORECASE,
)


def _parse_cgroup_paths(text: str | None) -> _CgroupRefs:
    if not text:
        return _CgroupRefs(paths=[], pod_uid=None, container_ids=[])
    paths: list[str] = []
    container_ids: list[str] = []
    pod_uid: str | None = None
    for line in text.splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        path = parts[2].strip()
        if not path:
            continue
        paths.append(path)
        if pod_uid is None:
            pod_match = _POD_UID_RE.search(path)
            if pod_match:
                pod_uid = pod_match.group("uid")
        for match in _CONTAINER_ID_RE.finditer(path):
            container_ids.append(match.group("id"))
        scope_match = re.search(r"([0-9a-f]{12,64})(?:\.scope)?$", path, re.IGNORECASE)
        if scope_match:
            container_ids.append(scope_match.group(1))
    return _CgroupRefs(
        paths=paths,
        pod_uid=pod_uid,
        container_ids=list(dict.fromkeys(container_ids)),
    )


_CONTAINER_STATE_FIELDS = (
    ("reason", "reason"),
    ("message", "message"),
    ("exitCode", "exit_code"),
    ("signal", "signal"),
    ("startedAt", "started_at"),
    ("finishedAt", "finished_at"),
)


def _normalize_container_state(value: Any) -> dict[str, Any] | None:
    """Expand a containerState into the reason, exit code, and timing under it.

    The API nests every useful field one level below running/waiting/terminated,
    so keeping only the key name discards the whole answer to "why is this not
    running": OOMKilled and exit 137, ImagePullBackOff and the image it could not
    pull, CreateContainerConfigError and the missing key (node-stats-mcp#7965).
    """
    if not isinstance(value, dict) or not value:
        return None
    state_type = next(iter(value), None)
    detail = value.get(state_type) if state_type else None
    normalized: dict[str, Any] = {"type": state_type}
    if isinstance(detail, dict):
        for api_key, out_key in _CONTAINER_STATE_FIELDS:
            if api_key in detail:
                normalized[out_key] = detail[api_key]
    return normalized


def _normalize_pod_containers(
    specs: Any, statuses: dict[Any, dict[str, Any]]
) -> tuple[list[dict[str, Any]], int]:
    containers: list[dict[str, Any]] = []
    restart_total = 0
    if not isinstance(specs, list):
        return containers, restart_total
    for container in specs:
        if not isinstance(container, dict):
            continue
        name = container.get("name")
        container_status = statuses.get(name, {})
        restart_count = int(container_status.get("restartCount") or 0)
        restart_total += restart_count
        containers.append(
            {
                "name": name,
                "image": container.get("image"),
                "ready": bool(container_status.get("ready")),
                "restart_count": restart_count,
                "container_id": _normalize_container_id(container_status.get("containerID")),
                "state": next(iter(container_status.get("state", {})), None),
                "state_detail": _normalize_container_state(container_status.get("state")),
                "last_state": _normalize_container_state(container_status.get("lastState")),
            }
        )
    return containers, restart_total


def _normalize_pod(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get("metadata", {})
    status = item.get("status", {})
    spec = item.get("spec", {})
    statuses = {
        c.get("name"): c for c in status.get("containerStatuses", []) if isinstance(c, dict)
    }
    init_statuses = {
        c.get("name"): c for c in status.get("initContainerStatuses", []) if isinstance(c, dict)
    }
    containers, restart_total = _normalize_pod_containers(spec.get("containers"), statuses)
    # Separate list: restart_count has always meant app-container restarts,
    # and Init:CrashLoopBackOff is its own diagnosis.
    init_containers, _ = _normalize_pod_containers(spec.get("initContainers"), init_statuses)
    created = _parse_timestamp(metadata.get("creationTimestamp"))
    now = datetime.now(UTC)
    age_seconds = (now - created).total_seconds() if created else None
    return {
        "namespace": metadata.get("namespace"),
        "pod": metadata.get("name"),
        "phase": status.get("phase"),
        "node": spec.get("nodeName"),
        "restart_count": restart_total,
        "pod_ip": status.get("podIP"),
        "created_at": created.isoformat() if created else None,
        "age_seconds": int(age_seconds) if age_seconds is not None else None,
        "age": _format_age(age_seconds),
        "reason": status.get("reason"),
        "message": status.get("message"),
        "containers": containers,
        "init_containers": init_containers,
    }


def _pod_indexes(pods: list[dict[str, Any]]) -> tuple[PodContainerIndex, PodUidIndex]:
    by_container_id: PodContainerIndex = {}
    by_pod_uid: PodUidIndex = {}
    for pod in pods:
        uid = None
        if isinstance(pod, dict):
            uid = pod.get("uid")
        if not uid:
            continue
        by_pod_uid[str(uid)] = pod
        for container in pod.get("containers", []):
            container_id = container.get("container_id")
            if container_id:
                by_container_id[str(container_id)] = (pod, container)
    return by_container_id, by_pod_uid


def _pod_uid_from_item(item: dict[str, Any]) -> str | None:
    metadata = item.get("metadata", {})
    uid = metadata.get("uid")
    return str(uid) if uid else None


def _normalize_pod_for_index(item: dict[str, Any]) -> dict[str, Any]:
    pod = _normalize_pod(item)
    pod["uid"] = _pod_uid_from_item(item)
    return pod


def _k8s_pod_inventory() -> tuple[list[dict[str, Any]], PodContainerIndex, PodUidIndex, list[str]]:
    items, errors = _k8s_list("/api/v1/pods")
    pods = [_normalize_pod_for_index(item) for item in items]
    by_container_id, by_pod_uid = _pod_indexes(pods)
    return pods, by_container_id, by_pod_uid, errors


def _pod_pvc_mounts(items: list[dict[str, Any]]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    mounts: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        metadata = item.get("metadata", {})
        spec = item.get("spec", {})
        status = item.get("status", {})
        namespace = metadata.get("namespace")
        pod = metadata.get("name")
        if not namespace or not pod:
            continue
        claims_by_volume: dict[str, str] = {}
        for volume in spec.get("volumes", []):
            if not isinstance(volume, dict):
                continue
            claim = volume.get("persistentVolumeClaim")
            if not isinstance(claim, dict):
                continue
            volume_name = volume.get("name")
            claim_name = claim.get("claimName")
            if volume_name and claim_name:
                claims_by_volume[str(volume_name)] = str(claim_name)
        for container_type, containers in (
            ("container", spec.get("containers", [])),
            ("init_container", spec.get("initContainers", [])),
            ("ephemeral_container", spec.get("ephemeralContainers", [])),
        ):
            for container in containers:
                if not isinstance(container, dict):
                    continue
                for mount in container.get("volumeMounts", []):
                    if not isinstance(mount, dict):
                        continue
                    volume_name = mount.get("name")
                    claim_name = claims_by_volume.get(str(volume_name))
                    if not claim_name:
                        continue
                    mounts[(str(namespace), claim_name)].append(
                        {
                            "pod": str(pod),
                            "pod_uid": _pod_uid_from_item(item),
                            "phase": status.get("phase"),
                            "container": container.get("name"),
                            "container_type": container_type,
                            "volume": volume_name,
                            "mount_path": mount.get("mountPath"),
                            "read_only": bool(mount.get("readOnly")),
                        }
                    )
    return mounts


def _normalize_pvc(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get("metadata", {})
    spec = item.get("spec", {})
    status = item.get("status", {})
    return {
        "namespace": metadata.get("namespace"),
        "persistent_volume_claim": metadata.get("name"),
        "persistent_volume_claim_uid": metadata.get("uid"),
        "persistent_volume": spec.get("volumeName"),
        "storage_class": spec.get("storageClassName"),
        "phase": status.get("phase"),
        "deletion_timestamp": metadata.get("deletionTimestamp"),
        "finalizers": (metadata.get("finalizers") or [])[:100],
        "access_modes": (spec.get("accessModes") or [])[:100],
        "volume_mode": spec.get("volumeMode"),
        "conditions": _normalize_conditions(status.get("conditions")),
        "requested_bytes": _parse_quantity(
            spec.get("resources", {}).get("requests", {}).get("storage")
        ),
        "capacity_bytes": _parse_quantity(status.get("capacity", {}).get("storage")),
    }


def _normalize_pv(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get("metadata", {})
    spec = item.get("spec", {})
    status = item.get("status", {})
    claim = spec.get("claimRef", {})
    host_path = spec.get("hostPath", {}).get("path")
    local_path = spec.get("local", {}).get("path")
    return {
        "persistent_volume": metadata.get("name"),
        "persistent_volume_uid": metadata.get("uid"),
        "namespace": claim.get("namespace"),
        "persistent_volume_claim": claim.get("name"),
        "persistent_volume_claim_uid": claim.get("uid"),
        "storage_class": spec.get("storageClassName"),
        "phase": status.get("phase"),
        "deletion_timestamp": metadata.get("deletionTimestamp"),
        "finalizers": (metadata.get("finalizers") or [])[:100],
        "access_modes": (spec.get("accessModes") or [])[:100],
        "volume_mode": spec.get("volumeMode"),
        "reclaim_policy": spec.get("persistentVolumeReclaimPolicy"),
        "status_reason": status.get("reason"),
        "status_message": status.get("message"),
        "capacity_bytes": _parse_quantity(spec.get("capacity", {}).get("storage")),
        "local_path": host_path or local_path,
        "local_path_source": "hostPath" if host_path else "local" if local_path else None,
    }


def _match_pod_container(
    refs: _CgroupRefs,
    by_container_id: PodContainerIndex,
    by_pod_uid: PodUidIndex,
) -> _K8sAuthRef | None:
    for container_id in refs.container_ids:
        container_match = by_container_id.get(str(container_id))
        if container_match is not None:
            pod, container = container_match
            return _K8sAuthRef(
                namespace=pod.get("namespace"),
                pod=pod.get("pod"),
                container=container.get("name"),
                pod_uid=pod.get("uid"),
                container_id=str(container_id),
                matched_by="container_id",
            )
    pod_uid = refs.pod_uid
    if pod_uid:
        pod_entry = by_pod_uid.get(str(pod_uid))
        if pod_entry is not None:
            container_name = None
            if len(pod_entry.get("containers", [])) == 1:
                container_name = pod_entry["containers"][0].get("name")
            return _K8sAuthRef(
                namespace=pod_entry.get("namespace"),
                pod=pod_entry.get("pod"),
                container=container_name,
                pod_uid=pod_entry.get("uid"),
                container_id=None,
                matched_by="pod_uid",
            )
    return None


def _iter_host_processes() -> list[dict[str, Any]]:
    processes: list[dict[str, Any]] = []
    for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent"]):
        info = dict(proc.info)
        try:
            rss_bytes = proc.memory_info().rss
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            rss_bytes = None
        info["rss_bytes"] = rss_bytes
        processes.append(info)
    return processes


def _process_inventory(sort_by: str = "memory") -> tuple[list[dict[str, Any]], list[str]]:
    _, by_container_id, by_pod_uid, errors = _k8s_pod_inventory()
    processes = []
    for proc in _iter_host_processes():
        pid = proc.get("pid")
        cgroup_text = _read_host_text(f"/proc/{pid}/cgroup") if pid else None
        refs = _parse_cgroup_paths(cgroup_text)
        attribution = _match_pod_container(refs, by_container_id, by_pod_uid)
        if attribution:
            proc["kubernetes"] = {
                "namespace": attribution.namespace,
                "pod": attribution.pod,
                "container": attribution.container,
                "pod_uid": attribution.pod_uid,
                "container_id": attribution.container_id,
                "matched_by": attribution.matched_by,
            }
        else:
            proc["kubernetes"] = None
        proc["cgroup"] = {
            "pod_uid": refs.pod_uid,
            "container_ids": refs.container_ids,
            "paths": refs.paths,
        }
        processes.append(proc)
    if sort_by == "memory":
        processes.sort(key=lambda p: p.get("rss_bytes") or 0, reverse=True)
    else:
        processes.sort(key=lambda p: p.get("cpu_percent") or 0.0, reverse=True)
    return processes, errors


def _k8s_pod_metrics() -> tuple[list[dict[str, Any]], list[str]]:
    metrics, errors = _k8s_list("/apis/metrics.k8s.io/v1beta1/pods")
    return metrics, errors


def _k8s_container_memory_from_metrics() -> tuple[list[dict[str, Any]], list[str]]:
    metrics, errors = _k8s_pod_metrics()
    containers: list[dict[str, Any]] = []
    for item in metrics:
        metadata = item.get("metadata", {})
        for container in item.get("containers", []):
            usage = container.get("usage", {})
            memory_bytes = _parse_quantity(usage.get("memory"))
            containers.append(
                {
                    "namespace": metadata.get("namespace"),
                    "pod": metadata.get("name"),
                    "container": container.get("name"),
                    "memory_bytes": memory_bytes,
                    "source": "metrics-server",
                }
            )
    containers.sort(key=lambda entry: entry.get("memory_bytes") or 0, reverse=True)
    return containers, errors


def _k8s_container_memory_from_processes() -> tuple[list[dict[str, Any]], list[str]]:
    _, by_container_id, by_pod_uid, errors = _k8s_pod_inventory()
    container_totals: dict[tuple[str | None, str | None, str | None], int] = defaultdict(int)
    for proc in _iter_host_processes():
        pid = proc.get("pid")
        if not pid:
            continue
        cgroup_text = _read_host_text(f"/proc/{pid}/cgroup")
        refs = _parse_cgroup_paths(cgroup_text)
        attribution = _match_pod_container(refs, by_container_id, by_pod_uid)
        if not attribution:
            continue
        key = (attribution.namespace, attribution.pod, attribution.container)
        container_totals[key] += int(proc.get("rss_bytes") or 0)

    containers = [
        {
            "namespace": namespace,
            "pod": pod,
            "container": container,
            "memory_bytes": memory_bytes,
            "source": "cgroup-rss",
        }
        for (namespace, pod, container), memory_bytes in container_totals.items()
    ]
    containers.sort(key=lambda entry: entry.get("memory_bytes") or 0, reverse=True)
    return containers, errors


def _k8s_container_memory() -> dict[str, Any]:
    containers, errors = _k8s_container_memory_from_metrics()
    source = "metrics-server"
    if not containers:
        containers, fallback_errors = _k8s_container_memory_from_processes()
        errors.extend(fallback_errors)
        source = "cgroup-rss" if containers else "unavailable"
    return {"source": source, "containers": containers, "errors": errors}


def get_k3s_pods(
    namespace: str | None = None,
    name: str | None = None,
    name_prefix: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Pods with container state, failure reason, exit code, and restart history.

    Narrow with namespace, an exact name, or a name prefix; the namespace filter
    is applied at the API, not after the fact. Each container carries state_detail
    and last_state, which name OOMKilled, ImagePullBackOff, CreateContainerConfigError
    and the exit code behind a crashloop. Init containers are listed separately.
    Not-Running pods sort first so a cap never truncates past the broken one.
    """
    return _k3s_pods(namespace, name, name_prefix, limit)


def get_k3s_container_memory() -> dict[str, Any]:
    """Approximate k3s container memory from metrics-server or host cgroup RSS."""
    return _k8s_container_memory()


def get_k3s_process_attribution(limit: int = 10, sort_by: str = "memory") -> dict[str, Any]:
    """Top host processes with cgroup-backed pod/container attribution when available."""
    if sort_by not in ("cpu", "memory"):
        raise ValueError("sort_by must be 'cpu' or 'memory'")
    processes, errors = _process_inventory(sort_by=sort_by)
    cap = max(1, min(limit, 100))
    return {"sort_by": sort_by, "processes": processes[:cap], "errors": errors}


async def get_k3s_volume_usage(
    limit: int = 20, max_entries_per_volume: int = _MAX_DU_ENTRIES
) -> dict[str, Any]:
    """Bounded local-volume disk usage joined to PVCs, PVs, namespaces, and pod mounts.

    The server scans only local paths beneath NODE_STATS_K3S_VOLUME_ROOTS. Callers
    can tune result and entry caps but cannot supply a filesystem path. The API
    reads and traversal run in a worker thread so fast node tools stay responsive.
    """
    return await asyncio.to_thread(
        _k3s_volume_usage,
        limit,
        max_entries_per_volume,
        schedule_host_snapshot=True,
    )


def get_node_pressure_stalls(limit: int = 20) -> dict[str, Any]:
    """Linux PSI, selected VM-pressure counters, and bounded block-device I/O counters."""
    return _node_contention(limit)


async def get_k3s_resource_usage(limit: int = 20) -> dict[str, Any]:
    """Bounded node and pod usage from this node's kubelet Summary API."""
    return await asyncio.to_thread(_k3s_resource_usage, limit)


async def get_k3s_node_health(limit: int = 50, max_age_hours: int = 24) -> dict[str, Any]:
    """Node conditions, taints, capacity, and bounded recent relevant events."""
    return await asyncio.to_thread(_k3s_node_health, limit, max_age_hours)


async def get_k3s_scheduled_work(limit: int = 50) -> dict[str, Any]:
    """Bounded Jobs and CronJobs with failure, activity, and last-success timing."""
    return await asyncio.to_thread(_k3s_scheduled_work, limit)


def get_configured_freshness() -> dict[str, Any]:
    """Freshness of server-configured host marker paths, without reading their content."""
    return _configured_freshness()


async def get_k3s_configured_conditions(
    limit_per_source: int = 50,
    namespace: str | None = None,
    name: str | None = None,
    source: str | None = None,
) -> dict[str, Any]:
    """Conditions for server-configured Kubernetes custom-resource types.

    Narrow with namespace, an exact object name, or a configured source name, so
    looking one ExternalSecret up does not page every one in the cluster.
    """
    return await asyncio.to_thread(
        _k3s_configured_conditions,
        limit_per_source,
        namespace,
        name,
        source,
    )


async def get_k3s_workloads(
    namespace: str | None = None,
    name: str | None = None,
    kind: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """Deployments, StatefulSets and DaemonSets with spec image and rollout state.

    spec_images is what the workload asks for, which is a different fact from the
    image a running pod reports: they diverge exactly when a rollout was applied
    and has not landed. rollout_complete folds desired, ready, updated and
    observedGeneration into the one answer. Incomplete rollouts sort first.
    """
    return await asyncio.to_thread(_k3s_workloads, namespace, name, kind, limit)


async def get_k3s_storage_claims(
    namespace: str | None = None, name: str | None = None, limit: int = 50
) -> dict[str, Any]:
    """PersistentVolumeClaims with phase, conditions, and their bound volume.

    The lifecycle view beside get_k3s_volume_usage, which measures disk rather
    than answering whether a claim bound. Unbound claims sort first.
    """
    return await asyncio.to_thread(_k3s_storage_claims, namespace, name, limit)


async def get_k3s_events(
    namespace: str | None = None,
    kind: str | None = None,
    name: str | None = None,
    limit: int = 50,
    max_age_hours: int = 24,
) -> dict[str, Any]:
    """Cluster events scoped to a namespace or one object, warnings first.

    The object selector is the kubectl events --for shape: pass kind and name to
    get only the events attached to that object.
    """
    return await asyncio.to_thread(_k3s_events, namespace, kind, name, limit, max_age_hours)


async def get_k3s_namespaces(limit: int = 200) -> dict[str, Any]:
    """Namespaces with phase, age, deletion timestamp, and finalizers.

    A namespace stuck Terminating is readable here: the finalizers holding it are
    on the record rather than inferred from the phase.
    """
    return await asyncio.to_thread(_k3s_namespaces, limit)


async def get_k3s_network(
    namespace: str | None = None, name: str | None = None, limit: int = 50
) -> dict[str, Any]:
    """Services, Ingresses and EndpointSlices for the routing path to a workload.

    EndpointSlices carry ready_endpoint_count, which is how a Service that
    resolves and answers nothing becomes visible. name also matches an
    EndpointSlice by the Service it backs.
    """
    return await asyncio.to_thread(_k3s_network, namespace, name, limit)


async def get_k3s_logs(
    namespace: str,
    pod: str,
    container: str | None = None,
    tail_lines: int = 200,
    previous: bool = False,
) -> dict[str, Any]:
    """Bounded, redacted container logs for one pod.

    previous=True reads the container that died rather than the one that replaced
    it, which is where a crashloop explains itself. Output is capped at
    NODE_STATS_K3S_LOG_MAX_BYTES, truncation is reported rather than silent, and
    assignment-shaped secrets plus JWT, forge and AWS key literals are replaced
    before the text leaves the cluster. Redaction is a backstop, not a guarantee:
    a workload that prints a credential in an unrecognised shape still prints it.
    """
    return await asyncio.to_thread(_k3s_logs, namespace, pod, container, tail_lines, previous)


def _allowed_roots() -> list[Path]:
    return [Path(ROOTFS).joinpath(r.lstrip("/")).resolve() for r in _READABLE_ROOTS]


def _resolve_readable(path: str) -> Path:
    """Resolve `path` under ROOTFS and confirm it sits under an allowed root.

    Raises ValueError (surfaced to the caller as a tool error) when file reads
    are disabled or the target escapes the allowlist.
    """
    roots = _allowed_roots()
    if not roots:
        raise ValueError("file reads are disabled (NODE_STATS_READABLE_ROOTS is empty)")
    target = Path(ROOTFS).joinpath(path.lstrip("/")).resolve()
    if not any(target == root or root in target.parents for root in roots):
        raise ValueError(f"path {path!r} is outside the readable-root allowlist")
    return target


def _allocated_bytes(path_stat: os.stat_result) -> int:
    blocks = getattr(path_stat, "st_blocks", None)
    if blocks is not None:
        return int(blocks) * 512
    return int(path_stat.st_size)


def _public_host_path(path: Path) -> str:
    try:
        relative = path.relative_to(Path(ROOTFS))
    except ValueError:
        return str(path)
    return "/" + relative.as_posix()


def _filesystem_pressure(path: str) -> dict[str, Any]:
    target = _host_path(path)
    statvfs = getattr(os, "statvfs", None)
    if statvfs is None:
        disk = psutil.disk_usage(str(target))
        total = disk.total
        free = disk.free
        available = disk.free
        reserved = 0
        inodes_total = 0
        inodes_free = 0
        inodes_available = 0
    else:
        fs = statvfs(target)
        total = fs.f_frsize * fs.f_blocks
        free = fs.f_frsize * fs.f_bfree
        available = fs.f_frsize * fs.f_bavail
        reserved = free - available
        inodes_total = fs.f_files
        inodes_free = fs.f_ffree
        inodes_available = fs.f_favail
    pressure_used = total - available
    used_percent = (pressure_used / total * 100.0) if total else 0.0
    warn_used = int(total * (_DISK_WARN_PERCENT / 100.0))
    critical_used = int(total * (_DISK_CRITICAL_PERCENT / 100.0))
    inode_percent = (
        ((inodes_total - inodes_available) / inodes_total) * 100.0 if inodes_total else 0.0
    )
    if used_percent >= _DISK_CRITICAL_PERCENT:
        status = "critical"
    elif used_percent >= _DISK_WARN_PERCENT:
        status = "warning"
    else:
        status = "ok"
    return {
        "path": path,
        "total_bytes": total,
        "free_bytes": free,
        "available_bytes": available,
        "reserved_bytes": reserved,
        "pressure_used_bytes": pressure_used,
        "used_percent": used_percent,
        "status": status,
        "warn_percent": _DISK_WARN_PERCENT,
        "critical_percent": _DISK_CRITICAL_PERCENT,
        "bytes_until_warn": warn_used - pressure_used,
        "bytes_until_critical": critical_used - pressure_used,
        "bytes_over_warn": max(0, pressure_used - warn_used),
        "bytes_over_critical": max(0, pressure_used - critical_used),
        "inodes_total": inodes_total,
        "inodes_free": inodes_free,
        "inodes_available": inodes_available,
        "inodes_used_percent": inode_percent,
    }


def _scan_result(path: Path, exists: bool) -> dict[str, Any]:
    return {
        "path": _public_host_path(path),
        "exists": exists,
        "size_bytes": 0,
        "entries_scanned": 0,
        "permission_errors": 0,
        "scan_errors": 0,
        "errors": [],
        "skipped_different_filesystem": 0,
        "truncated": False,
        "truncation_reason": None,
        "timed_out": False,
    }


def _stop_reason(budget: _ScanBudget) -> str | None:
    if time.monotonic() >= budget.deadline:
        return "timeout"
    if budget.entries_scanned >= budget.max_entries:
        return "global_entry_budget"
    return None


def _record_scan_error(result: dict[str, Any], exc: OSError) -> None:
    result["scan_errors"] += 1
    if len(result["errors"]) < 10:
        result["errors"].append(str(exc))


def _du_path(
    path: Path, max_entries: int, root_device: int | None, budget: _ScanBudget
) -> dict[str, Any]:
    try:
        exists = path.exists()
    except OSError as exc:
        exists = False
        result = _scan_result(path, exists=False)
        _record_scan_error(result, exc)
        return result
    if not exists:
        return _scan_result(path, exists=False)

    result = _scan_result(path, exists=True)
    stack = [path]
    while stack:
        if reason := _stop_reason(budget):
            result["truncated"] = True
            result["truncation_reason"] = reason
            result["timed_out"] = reason == "timeout"
            break
        current = stack.pop()
        try:
            current_stat = current.lstat()
        except FileNotFoundError:
            continue
        except PermissionError:
            result["permission_errors"] += 1
            continue
        except OSError as exc:
            _record_scan_error(result, exc)
            continue
        if root_device is not None and current_stat.st_dev != root_device:
            result["skipped_different_filesystem"] += 1
            continue
        result["size_bytes"] += _allocated_bytes(current_stat)
        result["entries_scanned"] += 1
        budget.entries_scanned += 1
        if result["entries_scanned"] >= max_entries:
            result["truncated"] = True
            result["truncation_reason"] = "per_path_entry_cap"
            break
        if budget.entries_scanned >= budget.max_entries:
            result["truncated"] = True
            result["truncation_reason"] = "global_entry_budget"
            break
        if not stat.S_ISDIR(current_stat.st_mode):
            continue
        try:
            with os.scandir(current) as children:
                for child in children:
                    if reason := _stop_reason(budget):
                        result["truncated"] = True
                        result["truncation_reason"] = reason
                        result["timed_out"] = reason == "timeout"
                        break
                    stack.append(Path(child.path))
        except PermissionError:
            result["permission_errors"] += 1
        except FileNotFoundError:
            continue
        except OSError as exc:
            _record_scan_error(result, exc)

    return result


def _coalesced_pressure_paths() -> tuple[list[Path], list[dict[str, str]]]:
    """Keep only shallow fixed roots so nested paths are not scanned twice."""
    configured = [(_host_path(path), path) for path in _PRESSURE_PATHS]
    selected: list[Path] = []
    skipped: list[dict[str, str]] = []
    for path, configured_path in sorted(configured, key=lambda item: len(item[0].parts)):
        parent = next((candidate for candidate in selected if candidate in path.parents), None)
        if parent is None and path not in selected:
            selected.append(path)
            continue
        skipped.append(
            {
                "path": configured_path,
                "covered_by": _public_host_path(parent if parent is not None else path),
            }
        )
    return selected, skipped


def _pressure_root_result(path: Path, exists: bool) -> dict[str, Any]:
    return {
        **_scan_result(path, exists),
        "children": [],
        "children_discovered": 0,
        "children_returned": 0,
        "child_results_truncated": False,
        "discovery_truncated": False,
        "discovery_truncation_reason": None,
        "discovery_timed_out": False,
    }


def _pressure_root_children(
    root: Path, max_children: int, deadline: float
) -> tuple[dict[str, Any], list[tuple[Path, int | None]]]:
    """Discover one level beneath one fixed root without following symlinks."""
    try:
        root_stat = root.lstat()
    except FileNotFoundError:
        return _pressure_root_result(root, exists=False), []
    except PermissionError:
        result = _pressure_root_result(root, exists=False)
        result["permission_errors"] += 1
        return result, []
    except OSError as exc:
        result = _pressure_root_result(root, exists=False)
        _record_scan_error(result, exc)
        return result, []

    result = _pressure_root_result(root, exists=True)
    root_device = root_stat.st_dev
    if not stat.S_ISDIR(root_stat.st_mode):
        result["children_discovered"] = 1
        return result, [(root, root_device)]

    children: list[tuple[Path, int | None]] = []
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                if time.monotonic() >= deadline:
                    result["discovery_truncated"] = True
                    result["discovery_truncation_reason"] = "timeout"
                    result["discovery_timed_out"] = True
                    break
                if len(children) >= max_children:
                    result["discovery_truncated"] = True
                    result["discovery_truncation_reason"] = "child_cap"
                    break
                children.append((Path(entry.path), root_device))
    except PermissionError:
        result["permission_errors"] += 1
    except FileNotFoundError:
        result["exists"] = False
    except OSError as exc:
        _record_scan_error(result, exc)
    children.sort(key=lambda item: str(item[0]))
    result["children_discovered"] = len(children)
    return result, children


def _scan_pressure_children(
    children: list[tuple[Path, int | None]],
    max_entries_per_child: int,
    deadline: float,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Give every discovered child an independent fair share of remaining work."""
    total_budget = max(1, _MAX_DU_TOTAL_ENTRIES)
    if not children:
        return {}, {
            "max_entries_per_child": 0,
            "total_entries_scanned": 0,
            "time_slice_seconds": 0.0,
            "timed_out": False,
            "truncated": False,
            "scan_errors": 0,
            "permission_errors": 0,
            "skipped_different_filesystem": 0,
        }

    selected_children = children[:total_budget]
    unscanned_children = children[total_budget:]
    entry_budget = max(
        1,
        min(
            max_entries_per_child,
            _MAX_DU_ENTRIES,
            max(1, total_budget // len(selected_children)),
        ),
    )
    remaining_seconds = max(0.001, deadline - time.monotonic())
    time_slice_seconds = max(0.001, remaining_seconds / len(selected_children))
    scans: dict[str, dict[str, Any]] = {}
    total_entries_scanned = 0
    for path, root_device in selected_children:
        budget = _ScanBudget(
            max_entries=entry_budget,
            deadline=time.monotonic() + time_slice_seconds,
        )
        scan = _du_path(path, entry_budget, root_device, budget)
        scans[str(path)] = scan
        total_entries_scanned += budget.entries_scanned
    for path, _ in unscanned_children:
        scan = _scan_result(path, exists=True)
        scan["truncated"] = True
        scan["truncation_reason"] = "global_entry_budget"
        scans[str(path)] = scan
    return scans, {
        "max_entries_per_child": entry_budget,
        "total_entries_scanned": total_entries_scanned,
        "time_slice_seconds": time_slice_seconds,
        "timed_out": any(scan["timed_out"] for scan in scans.values()),
        "truncated": any(scan["truncated"] for scan in scans.values()),
        "scan_errors": sum(scan["scan_errors"] for scan in scans.values()),
        "permission_errors": sum(scan["permission_errors"] for scan in scans.values()),
        "skipped_different_filesystem": sum(
            scan["skipped_different_filesystem"] for scan in scans.values()
        ),
    }


def _pressure_path_usage(limit: int, max_entries_per_path: int) -> dict[str, Any]:
    """Attribute fixed pressure roots to their immediate children with fair limits."""
    child_limit = max(1, min(limit, 100))
    max_children_per_root = max(1, _MAX_PRESSURE_CHILDREN_PER_ROOT)
    total_budget = max(1, _MAX_DU_TOTAL_ENTRIES)
    timeout_seconds = max(0.001, _DU_TIMEOUT_SECONDS)
    request_deadline = time.monotonic() + timeout_seconds
    scan_paths, skipped_nested_paths = _coalesced_pressure_paths()
    discovery_time_slice_seconds = (
        max(0.001, timeout_seconds / (2 * len(scan_paths))) if scan_paths else 0.0
    )
    roots: list[tuple[dict[str, Any], list[tuple[Path, int | None]]]] = []
    for path in scan_paths:
        root, root_children = _pressure_root_children(
            path,
            max_children_per_root,
            time.monotonic() + discovery_time_slice_seconds,
        )
        roots.append((root, root_children))

    children = [
        root_children[index]
        for index in range(max((len(root_children) for _, root_children in roots), default=0))
        for _, root_children in roots
        if index < len(root_children)
    ]

    scans, scan_summary = _scan_pressure_children(
        children,
        max_entries_per_path,
        request_deadline,
    )
    paths: list[dict[str, Any]] = []
    for root, root_children in roots:
        child_scans = [scans[str(path)] for path, _ in root_children if str(path) in scans]
        child_scans.sort(key=lambda item: (-item["size_bytes"], item["path"]))
        root["children"] = child_scans[:child_limit]
        root["children_returned"] = len(root["children"])
        root["child_results_truncated"] = len(child_scans) > child_limit
        root["size_bytes"] = sum(child["size_bytes"] for child in child_scans)
        root["entries_scanned"] = sum(child["entries_scanned"] for child in child_scans)
        root["permission_errors"] += sum(child["permission_errors"] for child in child_scans)
        root["scan_errors"] += sum(child["scan_errors"] for child in child_scans)
        root["skipped_different_filesystem"] = sum(
            child["skipped_different_filesystem"] for child in child_scans
        )
        child_truncated = any(child["truncated"] for child in child_scans)
        root["truncated"] = root["discovery_truncated"] or child_truncated
        root["truncation_reason"] = root["discovery_truncation_reason"]
        if root["truncation_reason"] is None and child_truncated:
            root["truncation_reason"] = "child_scan_truncated"
        root["timed_out"] = root["discovery_timed_out"] or any(
            child["timed_out"] for child in child_scans
        )
        paths.append(root)

    discovery_scan_errors = (
        sum(root["scan_errors"] for root, _ in roots) - scan_summary["scan_errors"]
    )
    discovery_permission_errors = (
        sum(root["permission_errors"] for root, _ in roots) - scan_summary["permission_errors"]
    )
    discovery_truncated = any(root["discovery_truncated"] for root, _ in roots)
    timed_out = any(root["timed_out"] for root, _ in roots)
    return {
        "paths": paths,
        "configured_paths": list(_PRESSURE_PATHS),
        "skipped_nested_paths": skipped_nested_paths,
        "limit_per_root": child_limit,
        "max_children_per_root": max_children_per_root,
        "max_entries_per_path": scan_summary["max_entries_per_child"],
        "max_entries_per_child": scan_summary["max_entries_per_child"],
        "max_total_entries": total_budget,
        "total_entries_scanned": scan_summary["total_entries_scanned"],
        "timeout_seconds": timeout_seconds,
        "discovery_time_slice_seconds": discovery_time_slice_seconds,
        "time_slice_seconds": scan_summary["time_slice_seconds"],
        "timed_out": timed_out,
        "truncated": discovery_truncated or scan_summary["truncated"],
        "scan_errors": discovery_scan_errors + scan_summary["scan_errors"],
        "permission_errors": discovery_permission_errors + scan_summary["permission_errors"],
        "skipped_different_filesystem": scan_summary["skipped_different_filesystem"],
        "same_filesystem_only": True,
    }


def _resolved_k3s_volume_roots() -> list[Path]:
    roots: list[Path] = []
    for configured in _K3S_VOLUME_ROOTS:
        root = _host_path(configured).resolve()
        if root not in roots:
            roots.append(root)
    return roots


def _safe_k3s_volume_path(path: str | None, roots: list[Path]) -> Path | None:
    if not path:
        return None
    candidate = _host_path(path).resolve()
    if any(root in candidate.parents for root in roots):
        return candidate
    return None


def _k3s_volume_root_children(
    roots: list[Path],
) -> tuple[list[Path], list[str], bool]:
    children: list[Path] = []
    errors: list[str] = []
    truncated = False
    cap = max(1, _MAX_K3S_VOLUME_PATHS)
    for root in roots:
        try:
            with os.scandir(root) as entries:
                for entry in entries:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    child = Path(entry.path).resolve()
                    if root not in child.parents:
                        continue
                    if len(children) >= cap:
                        truncated = True
                        break
                    children.append(child)
        except FileNotFoundError:
            continue
        except OSError as exc:
            errors.append(f"{_public_host_path(root)}: {exc}")
    children.sort(key=str)
    return children, errors, truncated


def _k3s_volume_inventory() -> tuple[list[dict[str, Any]], list[str]]:
    pod_items, pod_errors = _k8s_list("/api/v1/pods")
    pvc_items, pvc_errors = _k8s_list("/api/v1/persistentvolumeclaims")
    pv_items, pv_errors = _k8s_list("/api/v1/persistentvolumes")
    errors = [
        *(f"pods: {error}" for error in pod_errors),
        *(f"persistent volume claims: {error}" for error in pvc_errors),
        *(f"persistent volumes: {error}" for error in pv_errors),
    ]
    mounts = _pod_pvc_mounts(pod_items)
    pv_by_name = {
        str(pv["persistent_volume"]): pv
        for item in pv_items
        if (pv := _normalize_pv(item))["persistent_volume"]
    }
    volumes: list[dict[str, Any]] = []
    claimed_pvs: set[str] = set()
    for item in pvc_items:
        pvc = _normalize_pvc(item)
        namespace = pvc["namespace"]
        claim_name = pvc["persistent_volume_claim"]
        pv_name = pvc["persistent_volume"]
        pv = pv_by_name.get(str(pv_name), {}) if pv_name else {}
        if pv_name:
            claimed_pvs.add(str(pv_name))
        mount_key = (str(namespace), str(claim_name))
        volumes.append(
            {
                "namespace": namespace,
                "persistent_volume_claim": claim_name,
                "persistent_volume_claim_uid": pvc["persistent_volume_claim_uid"],
                "persistent_volume": pv_name,
                "persistent_volume_uid": pv.get("persistent_volume_uid"),
                "storage_class": pvc["storage_class"] or pv.get("storage_class"),
                "pvc_phase": pvc["phase"],
                "pv_phase": pv.get("phase"),
                "pvc_deletion_timestamp": pvc["deletion_timestamp"],
                "pv_deletion_timestamp": pv.get("deletion_timestamp"),
                "pvc_finalizers": pvc["finalizers"],
                "pv_finalizers": pv.get("finalizers", []),
                "pvc_conditions": pvc["conditions"],
                "access_modes": pvc["access_modes"] or pv.get("access_modes", []),
                "volume_mode": pvc["volume_mode"] or pv.get("volume_mode"),
                "reclaim_policy": pv.get("reclaim_policy"),
                "pv_status_reason": pv.get("status_reason"),
                "pv_status_message": pv.get("status_message"),
                "requested_bytes": pvc["requested_bytes"],
                "capacity_bytes": pvc["capacity_bytes"] or pv.get("capacity_bytes"),
                "local_path_source": pv.get("local_path_source"),
                "pod_mounts": mounts.get(mount_key, []),
                "_candidate_local_path": pv.get("local_path"),
            }
        )
    for pv_name, pv in pv_by_name.items():
        if pv_name in claimed_pvs:
            continue
        namespace = pv["namespace"]
        claim_name = pv["persistent_volume_claim"]
        mount_key = (str(namespace), str(claim_name))
        volumes.append(
            {
                "namespace": namespace,
                "persistent_volume_claim": claim_name,
                "persistent_volume_claim_uid": None,
                "persistent_volume": pv_name,
                "persistent_volume_uid": pv["persistent_volume_uid"],
                "storage_class": pv["storage_class"],
                "pvc_phase": None,
                "pv_phase": pv["phase"],
                "pvc_deletion_timestamp": None,
                "pv_deletion_timestamp": pv["deletion_timestamp"],
                "pvc_finalizers": [],
                "pv_finalizers": pv["finalizers"],
                "pvc_conditions": [],
                "access_modes": pv["access_modes"],
                "volume_mode": pv["volume_mode"],
                "reclaim_policy": pv["reclaim_policy"],
                "pv_status_reason": pv["status_reason"],
                "pv_status_message": pv["status_message"],
                "requested_bytes": None,
                "capacity_bytes": pv["capacity_bytes"],
                "local_path_source": pv["local_path_source"],
                "pod_mounts": mounts.get(mount_key, []),
                "_candidate_local_path": pv["local_path"],
            }
        )
    volumes.sort(
        key=lambda volume: (
            str(volume.get("namespace") or ""),
            str(volume.get("persistent_volume_claim") or ""),
            str(volume.get("persistent_volume") or ""),
        )
    )
    return volumes, errors


def _scan_k3s_volume_paths(
    paths: list[Path], max_entries_per_volume: int
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    if not paths:
        return {}, {
            "max_entries_per_volume": 0,
            "max_total_entries": max(1, _MAX_DU_TOTAL_ENTRIES),
            "total_entries_scanned": 0,
            "timeout_seconds": max(0.001, _DU_TIMEOUT_SECONDS),
            "time_slice_seconds": 0.0,
            "timed_out": False,
            "truncated": False,
            "scan_errors": 0,
            "permission_errors": 0,
        }
    total_budget = max(1, _MAX_DU_TOTAL_ENTRIES)
    entry_budget = max(
        1,
        min(
            max_entries_per_volume,
            _MAX_DU_ENTRIES,
            max(1, total_budget // len(paths)),
        ),
    )
    timeout_seconds = max(0.001, _DU_TIMEOUT_SECONDS)
    time_slice_seconds = max(0.001, timeout_seconds / len(paths))
    scans: dict[str, dict[str, Any]] = {}
    total_entries_scanned = 0
    for path in paths:
        try:
            root_device = path.lstat().st_dev
        except OSError:
            root_device = None
        budget = _ScanBudget(
            max_entries=entry_budget,
            deadline=time.monotonic() + time_slice_seconds,
        )
        scan = _du_path(path, entry_budget, root_device, budget)
        scans[str(path)] = scan
        total_entries_scanned += budget.entries_scanned
    return scans, {
        "max_entries_per_volume": entry_budget,
        "max_total_entries": total_budget,
        "total_entries_scanned": total_entries_scanned,
        "timeout_seconds": timeout_seconds,
        "time_slice_seconds": time_slice_seconds,
        "timed_out": any(scan["timed_out"] for scan in scans.values()),
        "truncated": any(scan["truncated"] for scan in scans.values()),
        "scan_errors": sum(scan["scan_errors"] for scan in scans.values()),
        "permission_errors": sum(scan["permission_errors"] for scan in scans.values()),
    }


def _k3s_volume_background_snapshot(limit: int) -> dict[str, Any]:
    configured_roots = {str(PurePosixPath(path)) for path in _K3S_VOLUME_ROOTS}
    profile = next(
        (
            candidate
            for candidate in _HOST_USAGE_PROFILES
            if str(PurePosixPath(candidate.path)) in configured_roots
        ),
        None,
    )
    if profile is None:
        return {
            "available": False,
            "profile": None,
            "reason": "no host usage profile matches a configured k3s volume root",
        }
    return {
        "available": True,
        **_HOST_USAGE_SNAPSHOTS.request(profile.name, limit=limit, refresh=False),
    }


def _k3s_volume_usage(
    limit: int,
    max_entries_per_volume: int,
    *,
    schedule_host_snapshot: bool,
) -> dict[str, Any]:
    volumes, errors = _k3s_volume_inventory()
    roots = _resolved_k3s_volume_roots()
    paths_by_key: dict[str, Path] = {}
    attributed_paths: set[Path] = set()
    for volume in volumes:
        candidate = volume.pop("_candidate_local_path")
        safe_path = _safe_k3s_volume_path(candidate, roots)
        if safe_path is None:
            volume["usage"] = None
            volume["scan_status"] = "outside_configured_roots" if candidate else "no_local_path"
            volume["usage_complete"] = False if candidate else None
            volume["usage_is_lower_bound"] = True if candidate else None
            continue
        volume["_local_path_key"] = str(safe_path)
        volume["local_path"] = _public_host_path(safe_path)
        paths_by_key.setdefault(str(safe_path), safe_path)
        attributed_paths.add(safe_path)

    root_children, discovery_errors, discovery_truncated = _k3s_volume_root_children(roots)
    errors.extend(f"volume discovery: {error}" for error in discovery_errors)
    unattributed_paths = [
        child
        for child in root_children
        if child not in attributed_paths
        and not any(child in attributed.parents for attributed in attributed_paths)
    ]
    for path in unattributed_paths:
        paths_by_key.setdefault(str(path), path)

    path_cap = max(1, _MAX_K3S_VOLUME_PATHS)
    scan_paths = list(paths_by_key.values())[:path_cap]
    path_limit_truncated = len(paths_by_key) > path_cap
    scans, scan_summary = _scan_k3s_volume_paths(scan_paths, max_entries_per_volume)

    counted_paths: set[str] = set()
    namespace_rollups: dict[str, dict[str, Any]] = {}
    for volume in volumes:
        path_key = volume.pop("_local_path_key", None)
        scan = scans.get(path_key) if path_key else None
        if path_key and scan is None:
            volume["usage"] = None
            volume["scan_status"] = "path_limit"
            volume["usage_complete"] = False
            volume["usage_is_lower_bound"] = True
        elif scan is not None:
            volume["usage"] = scan
            usage_complete = not (
                scan["truncated"] or scan["permission_errors"] or scan["scan_errors"]
            )
            volume["usage_complete"] = usage_complete
            volume["usage_is_lower_bound"] = not usage_complete
            volume["scan_status"] = (
                "missing" if not scan["exists"] else "scanned" if usage_complete else "partial"
            )
        namespace = volume.get("namespace")
        if not namespace:
            continue
        rollup = namespace_rollups.setdefault(
            str(namespace),
            {
                "namespace": str(namespace),
                "used_bytes": 0,
                "volume_count": 0,
                "truncated_volume_count": 0,
                "incomplete_volume_count": 0,
                "used_bytes_complete": True,
                "_pods": set(),
            },
        )
        rollup["volume_count"] += 1
        rollup["_pods"].update(
            str(mount["pod"]) for mount in volume["pod_mounts"] if mount.get("pod")
        )
        if scan is None:
            if path_key or volume["scan_status"] == "outside_configured_roots":
                rollup["used_bytes_complete"] = False
                rollup["incomplete_volume_count"] += 1
            continue
        if not volume["usage_complete"]:
            rollup["used_bytes_complete"] = False
            rollup["incomplete_volume_count"] += 1
        if path_key in counted_paths:
            continue
        counted_paths.add(path_key)
        rollup["used_bytes"] += scan["size_bytes"]
        if scan["truncated"]:
            rollup["truncated_volume_count"] += 1

    namespaces = []
    for rollup in namespace_rollups.values():
        pods = rollup.pop("_pods")
        rollup["pod_count"] = len(pods)
        rollup["used_bytes_is_lower_bound"] = not rollup["used_bytes_complete"]
        namespaces.append(rollup)
    namespaces.sort(key=lambda item: item["used_bytes"], reverse=True)

    volumes.sort(
        key=lambda volume: (
            volume["usage"]["size_bytes"] if volume.get("usage") else -1,
            str(volume.get("namespace") or ""),
            str(volume.get("persistent_volume_claim") or ""),
        ),
        reverse=True,
    )
    unattributed = [scans[str(path)] for path in unattributed_paths if str(path) in scans]
    unattributed.sort(key=lambda item: item["size_bytes"], reverse=True)
    cap = max(1, min(limit, 100))
    complete = not (
        errors
        or discovery_truncated
        or path_limit_truncated
        or scan_summary["truncated"]
        or scan_summary["scan_errors"]
        or scan_summary["permission_errors"]
        or any(
            volume["scan_status"] in {"outside_configured_roots", "path_limit", "partial"}
            for volume in volumes
        )
    )
    return {
        "volumes": volumes[:cap],
        "namespaces": namespaces,
        "unattributed_paths": unattributed[:cap],
        "configured_volume_roots": list(_K3S_VOLUME_ROOTS),
        "volume_count": len(volumes),
        "volume_results_truncated": len(volumes) > cap,
        "unattributed_path_count": len(unattributed_paths),
        "path_limit": path_cap,
        "paths_scanned": len(scan_paths),
        "discovery_truncated": discovery_truncated or path_limit_truncated,
        **scan_summary,
        "complete": complete,
        "totals_are_lower_bounds": not complete,
        "host_usage_snapshot": (
            _k3s_volume_background_snapshot(cap)
            if schedule_host_snapshot
            else {
                "available": False,
                "profile": None,
                "reason": "background snapshot scheduling is disabled in the exporter process",
            }
        ),
        "errors": errors,
        "same_filesystem_only": True,
    }


def get_cpu_info() -> dict[str, Any]:
    """CPU utilization, core counts, and per-core percentages for this node."""
    return {
        "percent": psutil.cpu_percent(interval=0.3),
        "per_core_percent": psutil.cpu_percent(interval=0.3, percpu=True),
        "logical_cores": psutil.cpu_count(),
        "physical_cores": psutil.cpu_count(logical=False),
        "load_avg_1_5_15": list(psutil.getloadavg()),
    }


def get_memory_info() -> dict[str, Any]:
    """Virtual and swap memory for this node (bytes and percent used)."""
    return {"virtual": psutil.virtual_memory()._asdict(), "swap": psutil.swap_memory()._asdict()}


def get_disk_info() -> dict[str, Any]:
    """Usage and mount info for the node's real filesystems (under ROOTFS).

    `options` carries the mount flags, which is where quota enforcement shows up
    (`prjquota`, `quota`, `usrquota`, `grpquota`) alongside `ro` and `noexec`.
    Without it, two directories on one shared filesystem are indistinguishable
    from two filesystems with separate ceilings. See docs/tools-host.md.
    """
    partitions = []
    for part in psutil.disk_partitions(all=False):
        mount = Path(ROOTFS).joinpath(part.mountpoint.lstrip("/"))
        try:
            usage = psutil.disk_usage(str(mount))._asdict()
        except (PermissionError, FileNotFoundError, OSError):
            usage = {}
        options = [opt for opt in getattr(part, "opts", "").split(",") if opt]
        partitions.append(
            {
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "options": options,
                "quota_enforced": any(opt.endswith("quota") for opt in options),
                "usage": usage,
            }
        )
    return {"partitions": partitions}


def get_filesystem_pressure() -> dict[str, Any]:
    """Root filesystem runway, inode use, and configurable pressure thresholds.

    This is the fast disk-pressure view for the node root mounted at ROOTFS. The
    default thresholds are 80/85 percent because kubelet image garbage collection
    starts to matter around that range on a single-filesystem k3s node.
    """
    return {"root": _filesystem_pressure("/")}


async def get_pressure_path_usage(
    limit: int = 20, max_entries_per_path: int = _MAX_DU_ENTRIES
) -> dict[str, Any]:
    """Bounded child usage beneath fixed host paths that commonly drive pressure.

    Traversal runs in a worker thread, leaving the MCP event loop available for
    fast tools such as get_filesystem_pressure. Every configured root gets a
    bounded discovery slice, then every immediate child gets a fair entry and
    time slice. Per-child results carry truncation, timeout, filesystem-skip,
    permission, and scan-error metadata. Nested configured roots are coalesced.
    The caller can tune only the child entry cap and per-root result count,
    never a raw path.
    """
    return await asyncio.to_thread(_pressure_path_usage, limit, max_entries_per_path)


def get_host_usage_breakdown(
    profile: str = "root",
    limit: int = 20,
    refresh: bool = False,
) -> dict[str, Any]:
    """Cached mount-aware usage for one server-configured host profile.

    The caller selects only a configured profile identifier. A missing, stale,
    or explicitly refreshed snapshot is scanned on a daemon worker thread while
    this request returns current cache state immediately. Every snapshot labels
    complete totals versus lower bounds and reports filesystem and mount
    exclusions, including bind-mount deduplication.
    """
    result = _HOST_USAGE_SNAPSHOTS.request(profile, limit=limit, refresh=refresh)
    result["configuration_errors"] = list(_HOST_USAGE_PROFILE_ERRORS)
    return result


async def get_host_log_usage(limit: int = 20) -> dict[str, Any]:
    """Bounded allocated usage for configured host log and journald roots.

    Journald roots nested beneath a configured log root are scanned separately
    and excluded from that parent, so aggregate bytes are not double-counted.
    Callers can cap returned child detail but cannot choose a path or widen the
    server-owned traversal limits.
    """
    result = await asyncio.to_thread(
        storage.scan_log_usage,
        ROOTFS,
        _HOST_LOG_PATHS,
        _JOURNAL_PATHS,
        max_entries=max(1, _MAX_HOST_LOG_ENTRIES),
        timeout_seconds=max(0.001, _HOST_LOG_TIMEOUT_SECONDS),
        max_children=max(1, _MAX_HOST_LOG_CHILDREN),
        limit=limit,
    )
    result["configuration_errors"] = list(_HOST_LOG_CONFIGURATION_ERRORS)
    if _HOST_LOG_CONFIGURATION_ERRORS:
        result["complete"] = False
        result["totals_are_lower_bounds"] = True
    return result


async def get_deleted_open_files(limit: int = 20) -> dict[str, Any]:
    """Bounded deleted-open-file summary from fixed proc metadata.

    Results deduplicate inodes and distinguish disk-backed reclaimable files
    from memfd, tmpfs, devices, container overlays, and other non-disk entries.
    Target paths are used only to match mount metadata and are never returned.
    Target contents are never opened.
    """
    return await asyncio.to_thread(
        storage.deleted_open_files,
        ROOTFS,
        max_pids=max(1, _MAX_DELETED_FILE_PIDS),
        max_fds_per_process=max(1, _MAX_DELETED_FILE_FDS),
        timeout_seconds=max(0.001, _DELETED_FILE_TIMEOUT_SECONDS),
        limit=limit,
    )


def get_network_info(interfaces: str = "default") -> dict[str, Any]:
    """Aggregate and per-interface network I/O counters for this node.

    `interfaces` takes "default" (drops per-pod veth churn), "all", or a
    comma-separated list such as "enp1s0,cni0,flannel.1,tailscale0". What was
    filtered is always reported, never silently dropped.

    These are LIFETIME counters. A non-zero drop count says nothing on its own,
    because the node's uptime is days: only movement between two readings is
    interpretable. See docs/tools-network.md.

    Reflects the node only when the pod runs with hostNetwork. Otherwise these
    are the pod's own interface counters.
    """
    per_nic = {name: c._asdict() for name, c in psutil.net_io_counters(pernic=True).items()}
    selected, filtering = _select_interfaces(per_nic, interfaces)
    return {
        "total": psutil.net_io_counters()._asdict(),
        "per_interface": selected,
        "filtering": filtering,
        "counter_semantics": "cumulative since boot",
    }


def get_conntrack() -> dict[str, Any]:
    """Netfilter connection tracking: count against max, and the per-CPU error totals.

    Read from procfs rather than the conntrack binary, so this adds no
    dependency. `totals` carries every column the running kernel publishes,
    summed across CPUs and parsed by column name, with insert_failed, drop and
    early_drop being the ones an egress fault turns up in.

    These are LIFETIME counters and only their movement is interpretable.
    Needs the host /proc mount and hostNetwork to describe the node.
    """
    return _conntrack()


async def get_resolver(namespace: str = "", pod: str = "") -> dict[str, Any]:
    """The node's DNS resolver, and optionally a pod's own as the container sees it.

    Give both `namespace` and `pod` to read that pod's resolv.conf through its
    host PID. A container's resolver differs from its host's, and that
    difference is what a DNS hypothesis turns on, so a mismatch in nameservers
    is stated in `notes` rather than left as two lists to diff.

    The pod read needs hostPID and the pod running on this node. When it cannot
    be satisfied the reason says which, rather than returning an empty result.
    """
    return await asyncio.to_thread(_resolver, namespace.strip(), pod.strip())


def get_socket_states() -> dict[str, Any]:
    """TCP socket counts by state, and ephemeral port usage against the configured range.

    Ephemeral exhaustion presents exactly like an upstream outage: new
    connections are refused while established ones keep working. The
    `ephemeral.utilization` figure is what separates the two.

    Needs hostNetwork to describe the node rather than the pod.
    """
    return _socket_states()


def _parse_conntrack_stat(text: str) -> tuple[dict[str, int], int]:
    """Sum the per-CPU rows of /proc/net/stat/nf_conntrack by column NAME.

    The file's first line is its own header, and the column set differs across
    kernel versions. Indexing by position works on the kernel it was written
    against and returns confident nonsense on any other, so the header is what
    is read here. Unknown columns are summed too rather than dropped, since a
    newer kernel's extra counter is still a counter.
    """
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) < 2:
        return {}, 0
    columns = lines[0].split()
    totals: dict[str, int] = dict.fromkeys(columns, 0)
    cpus = 0
    for line in lines[1:]:
        values = line.split()
        if len(values) != len(columns):
            continue
        cpus += 1
        for name, raw in zip(columns, values, strict=True):
            try:
                totals[name] += int(raw, 16)
            except ValueError:
                continue
    return totals, cpus


def _read_host_int(path: str) -> int | None:
    text = _read_host_text(path)
    if text is None:
        return None
    try:
        return int(text.strip())
    except ValueError:
        return None


def _conntrack() -> dict[str, Any]:
    count = _read_host_int(_CONNTRACK_COUNT_PATH)
    maximum = _read_host_int(_CONNTRACK_MAX_PATH)
    stat_text = _read_host_text(_CONNTRACK_STAT_PATH)
    totals, cpus = _parse_conntrack_stat(stat_text or "")

    notes: list[str] = []
    if count is None and maximum is None and not totals:
        notes.append(
            "nf_conntrack is not readable here. The module may be unloaded, or the "
            "pod may lack the host /proc mount and hostNetwork."
        )
    elif stat_text is None:
        # The sysctls can parse while the stat table is absent. Empty totals then
        # read as zero errors rather than as no reading. See docs/tools-network.md.
        notes.append(
            f"{_CONNTRACK_STAT_PATH} is not present, so insert_failed, drop and "
            "early_drop are UNREAD rather than zero. count and max above are real."
        )
    elif not totals:
        notes.append(
            f"{_CONNTRACK_STAT_PATH} was read but no per-CPU rows parsed, so "
            "insert_failed, drop and early_drop are UNREAD rather than zero."
        )
    utilization = None
    if count is not None and maximum:
        utilization = round(count / maximum, 4)
    return {
        "count": count,
        "max": maximum,
        "utilization": utilization,
        "cpus": cpus,
        # Summed across CPUs. Only movement is interpretable. See
        # docs/tools-network.md.
        "totals": totals,
        "notes": notes,
    }


def _ephemeral_port_range() -> dict[str, Any]:
    text = _read_host_text(_EPHEMERAL_RANGE_PATH)
    parts = (text or "").split()
    if len(parts) != 2:
        return {"low": None, "high": None, "size": None}
    try:
        low, high = int(parts[0]), int(parts[1])
    except ValueError:
        return {"low": None, "high": None, "size": None}
    return {"low": low, "high": high, "size": max(0, high - low + 1)}


def _socket_states() -> dict[str, Any]:
    ephemeral = _ephemeral_port_range()
    # Constant-cost summary, read first so it is present even when the
    # per-socket walk below is denied or too expensive to trust.
    summary = _parse_sockstat(_read_host_text(_SOCKSTAT_PATH) or "")
    states: dict[str, int] = {}
    local_ports: set[int] = set()
    notes: list[str] = []
    try:
        connections = psutil.net_connections(kind="tcp")
    except (psutil.AccessDenied, PermissionError):
        return {
            "states": {},
            "total": 0,
            "summary": summary,
            "ephemeral": ephemeral,
            "notes": [
                "Reading per-socket state was denied, so only the constant-cost "
                "sockstat summary is present. The walk needs hostNetwork and "
                "privilege to read /proc/net/tcp."
            ],
        }
    low, high = ephemeral["low"], ephemeral["high"]
    for conn in connections:
        states[conn.status] = states.get(conn.status, 0) + 1
        if conn.laddr and low is not None and high is not None:
            port = conn.laddr[1] if isinstance(conn.laddr, tuple) else conn.laddr.port
            if low <= port <= high:
                local_ports.add(port)
    if low is not None and ephemeral["size"]:
        ephemeral = {
            **ephemeral,
            "in_use": len(local_ports),
            "utilization": round(len(local_ports) / ephemeral["size"], 4),
        }
    return {
        "states": dict(sorted(states.items())),
        "total": len(connections),
        "summary": summary,
        "ephemeral": ephemeral,
        "notes": notes,
    }


def _parse_sockstat(text: str) -> dict[str, dict[str, int]]:
    """Parse /proc/net/sockstat, which is six labelled lines of key-value pairs.

    Constant cost regardless of socket count, unlike /proc/net/tcp which is one
    line per socket and is longest exactly when load peaks. Its `TCP: tw` field
    is TIME_WAIT, the number ephemeral exhaustion actually shows up in, so the
    cheap file carries the signal the expensive walk was wanted for.

    Parsed by the labels the file itself carries rather than by position, for
    the same reason the conntrack table is. See docs/tools-network.md.
    """
    out: dict[str, dict[str, int]] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        protocol, _, rest = line.partition(":")
        fields = rest.split()
        values: dict[str, int] = {}
        for index in range(0, len(fields) - 1, 2):
            try:
                values[fields[index]] = int(fields[index + 1])
            except ValueError:
                continue
        if values:
            out[protocol.strip()] = values
    return out


def _parse_resolv_conf(text: str) -> dict[str, Any]:
    """Parse resolv.conf into the fields a DNS hypothesis actually turns on."""
    nameservers: list[str] = []
    search: list[str] = []
    options: dict[str, Any] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        keyword, _, rest = line.partition(" ")
        keyword = keyword.strip().lower()
        rest = rest.strip()
        if keyword == "nameserver" and rest:
            nameservers.append(rest)
        elif keyword in {"search", "domain"} and rest:
            search.extend(rest.split())
        elif keyword == "options":
            for option in rest.split():
                name, sep, value = option.partition(":")
                options[name] = int(value) if sep and value.isdigit() else True
    return {
        "nameservers": nameservers,
        "search": search,
        "options": options,
        # ndots drives how many lookups a short name costs, which is the field a
        # resolver hypothesis usually turns on.
        "ndots": options.get("ndots"),
    }


def _pod_host_pid(namespace: str, pod: str) -> tuple[int | None, str | None]:
    """Find a host PID belonging to one pod, by matching cgroup pod UID.

    Needs hostPID. Returns the reason rather than a bare None so a caller can
    tell "no such pod" from "this pod runs on another node".
    """
    items, _by_container, by_pod_uid, _errors = _k8s_pod_inventory()
    wanted_uid: str | None = None
    for entry in items:
        if entry.get("namespace") == namespace and entry.get("pod") == pod:
            wanted_uid = entry.get("uid")
            break
    if wanted_uid is None:
        known = any(entry.get("namespace") == namespace for entry in items)
        if not known:
            return None, f"no pod {namespace}/{pod} is visible from this node"
        return None, f"pod {namespace}/{pod} was not found in this node's inventory"
    del by_pod_uid
    for proc in psutil.process_iter(["pid"]):
        pid = proc.info.get("pid")
        if not pid:
            continue
        refs = _parse_cgroup_paths(_read_host_text(f"/proc/{pid}/cgroup"))
        if refs.pod_uid and refs.pod_uid.lower() == str(wanted_uid).lower():
            return int(pid), None
    return None, (
        f"pod {namespace}/{pod} exists but no process of it was found on this node. "
        "It may be scheduled elsewhere, or this pod is not running with hostPID."
    )


def _resolver(namespace: str, pod: str) -> dict[str, Any]:
    node_text = _read_host_text(_RESOLV_CONF_PATH)
    result: dict[str, Any] = {
        "node": _parse_resolv_conf(node_text) if node_text else None,
        "pod": None,
        "notes": [],
    }
    if node_text is None:
        result["notes"].append(f"{_RESOLV_CONF_PATH} was not readable under ROOTFS")
    if not namespace or not pod:
        return result

    pid, reason = _pod_host_pid(namespace, pod)
    if pid is None:
        result["notes"].append(reason or "pod resolver unavailable")
        return result
    pod_text = _read_host_text(f"/proc/{pid}/root{_RESOLV_CONF_PATH}")
    if pod_text is None:
        result["notes"].append(
            f"found pid {pid} for {namespace}/{pod} but could not read its resolv.conf"
        )
        return result
    parsed = _parse_resolv_conf(pod_text)
    result["pod"] = {"namespace": namespace, "pod": pod, "pid": pid, **parsed}
    node = result["node"]
    if node and node.get("nameservers") != parsed.get("nameservers"):
        # The difference is the point of the tool, so it is stated rather than
        # left for the reader to diff two lists.
        result["notes"].append("pod and node nameservers differ")
    return result


def _select_interfaces(
    counters: dict[str, Any], interfaces: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Pick the interfaces worth returning, and say what was left out.

    A k3s node carries one veth per pod, which on kai-server is 140-plus entries
    and about 20 KB of response that no incident asks about. Virtual churn is
    dropped by default and the omission is reported rather than silent, so a
    caller never mistakes a filtered response for the whole picture.
    """
    requested = [name.strip() for name in interfaces.split(",") if name.strip()]
    if requested and requested != ["default"]:
        if requested == ["all"]:
            return dict(counters), {"mode": "all", "omitted": 0}
        selected = {name: counters[name] for name in requested if name in counters}
        missing = [name for name in requested if name not in counters]
        return selected, {"mode": "named", "requested": requested, "not_present": missing}

    kept = {
        name: value
        for name, value in counters.items()
        if not name.startswith(_VIRTUAL_INTERFACE_PREFIXES)
    }
    omitted = sorted(set(counters) - set(kept))
    return kept, {
        "mode": "default",
        "omitted": len(omitted),
        "omitted_prefixes": list(_VIRTUAL_INTERFACE_PREFIXES),
        "hint": 'pass interfaces="all" for every interface, or a comma-separated list',
    }


def get_top_processes(limit: int = 10, sort_by: str = "cpu") -> dict[str, Any]:
    """Top processes by 'cpu' or 'memory'. Needs hostPID to see node processes."""
    if sort_by not in ("cpu", "memory"):
        raise ValueError("sort_by must be 'cpu' or 'memory'")
    procs = []
    for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent"]):
        procs.append(proc.info)
    key = "cpu_percent" if sort_by == "cpu" else "memory_percent"
    procs.sort(key=lambda p: p.get(key) or 0.0, reverse=True)
    return {"sort_by": sort_by, "processes": procs[: max(1, min(limit, 100))]}


def get_system_snapshot() -> dict[str, Any]:
    """One-shot node overview: cpu, memory, load, boot time, uptime, users."""
    boot = psutil.boot_time()
    now = time.time()
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.3),
        "memory": psutil.virtual_memory()._asdict(),
        "load_avg_1_5_15": list(psutil.getloadavg()),
        "boot_time_epoch": boot,
        "uptime_seconds": now - boot,
        "logged_in_users": [u._asdict() for u in psutil.users()],
    }


def stat_path(path: str) -> dict[str, Any]:
    """Metadata (size, mode, mtime, type) for a path under the readable-root allowlist."""
    target = _resolve_readable(path)
    st = target.stat()
    return {
        "path": path,
        "exists": True,
        "size_bytes": st.st_size,
        "mode_octal": oct(st.st_mode & 0o777),
        "mtime_epoch": st.st_mtime,
        "is_dir": target.is_dir(),
        "is_file": target.is_file(),
    }


def read_text_head(path: str, max_bytes: int = _MAX_READ_BYTES) -> dict[str, Any]:
    """Read up to max_bytes of a text file under the readable-root allowlist (capped)."""
    target = _resolve_readable(path)
    cap = max(1, min(max_bytes, _MAX_READ_BYTES))
    data = target.read_bytes()[:cap]
    return {
        "path": path,
        "bytes_returned": len(data),
        "truncated": target.stat().st_size > len(data),
        "text": data.decode("utf-8", errors="replace"),
    }


# Register without rebinding the name, so the plain callables stay directly
# invocable: the SDK's decorator return type has varied across versions.
for _tool in (
    get_cpu_info,
    get_memory_info,
    get_disk_info,
    get_filesystem_pressure,
    get_pressure_path_usage,
    get_host_usage_breakdown,
    get_host_log_usage,
    get_deleted_open_files,
    get_network_info,
    get_conntrack,
    get_resolver,
    get_socket_states,
    get_top_processes,
    get_system_snapshot,
    get_k3s_pods,
    get_k3s_container_memory,
    get_k3s_process_attribution,
    get_k3s_volume_usage,
    get_node_pressure_stalls,
    get_k3s_resource_usage,
    get_k3s_node_health,
    get_k3s_scheduled_work,
    get_configured_freshness,
    get_k3s_configured_conditions,
    get_k3s_workloads,
    get_k3s_storage_claims,
    get_k3s_events,
    get_k3s_namespaces,
    get_k3s_network,
    get_k3s_logs,
    stat_path,
    read_text_head,
):
    mcp.tool()(_tool)


def main() -> None:
    """Run the MCP server over streamable-HTTP (endpoint served at /mcp)."""
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
