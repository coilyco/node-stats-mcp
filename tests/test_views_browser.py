"""MCP Apps views in a real browser: the View's own behavior, not the server contract.

A stand-in host page embeds each View in a sandboxed iframe, answers `ui/initialize`, and
sends `ui/notifications/tool-result`, the way an MCP Apps host does. The View HTML comes
from a real `resources/read`, so the page under test is what a host would receive.

Deselected by default (the `browser` marker). `just check-views` runs it and CI calls
that verb. A missing browser fails the run: a skip here would be a silent pass.
See docs/mcp-apps-views.md.
"""

from __future__ import annotations

import asyncio
import importlib
import json
from collections.abc import Callable, Iterator
from types import ModuleType
from typing import Any

import pytest
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import TextResourceContents
from playwright.sync_api import Browser, BrowserContext, Page, expect, sync_playwright
from pydantic import AnyUrl

pytestmark = pytest.mark.browser

GIB = 1024**3
HOST_URL = "https://host.test/"
PROTOCOL_VERSION = "2026-01-26"
# The spec's default CSP, carried by the host page: the iframe inherits it, so any
# request the View attempts is refused and logged.
HOST_CSP = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'"
HOST_PAGE = """<!doctype html>
<meta charset="utf-8">
<iframe id="view" sandbox="allow-scripts" style="width: 600px; height: 120px; border: 0"></iframe>
<script>
const frame = document.getElementById("view");
window.log = [];
window.hostContext = {};
window.hostCapabilities = {};
window.toolResults = {};
window.addEventListener("message", (event) => {
  const m = event.data;
  if (event.source !== frame.contentWindow || !m) return;
  window.log.push(m);
  if (m.method === "ui/initialize") {
    frame.contentWindow.postMessage({ jsonrpc: "2.0", id: m.id, result: {
      protocolVersion: "__PROTOCOL_VERSION__", hostInfo: { name: "test-host", version: "0" },
      hostCapabilities: window.hostCapabilities, hostContext: window.hostContext } }, "*");
  } else if (m.method === "ui/notifications/size-changed") {
    frame.style.height = m.params.height + "px";
  } else if (m.method === "tools/call") {
    const next = (window.toolResults[m.params.name] || []).shift();
    frame.contentWindow.postMessage(next === undefined
      ? { jsonrpc: "2.0", id: m.id,
          error: { code: -32602, message: "no result queued for " + m.params.name } }
      : { jsonrpc: "2.0", id: m.id, result: next }, "*");
  }
});
window.hostSend = (message) => frame.contentWindow.postMessage({ jsonrpc: "2.0", ...message }, "*");
window.loadView = (html) => { frame.srcdoc = html; };
</script>
""".replace("__PROTOCOL_VERSION__", PROTOCOL_VERSION)


def _usage(total_gib: int, percent: float) -> dict[str, Any]:
    total = total_gib * GIB
    used = int(total * percent / 100)
    return {"total": total, "used": used, "free": total - used, "percent": percent}


def _mount(device: str, mountpoint: str, fstype: str, usage: dict[str, Any]) -> dict[str, Any]:
    return {
        "device": device,
        "mountpoint": mountpoint,
        "fstype": fstype,
        "options": ["rw"],
        "quota_enforced": False,
        "usage": usage,
    }


UNREADABLE_MOUNTS = 57
CHARTED_ENTRIES = 4


def disk_payload() -> dict[str, Any]:
    """Shaped like kai-server: most mounts carry `usage: {}`, one device mounted twice."""
    root = _usage(500, 76.0)
    return {
        "partitions": [
            _mount("/dev/nvme0n1p2", "/", "ext4", root),
            _mount("/dev/nvme0n1p2", "/etc/hosts", "ext4", root),
            _mount("/dev/sdb1", "/mnt/data", "xfs", _usage(2000, 93.0)),
            _mount("tmpfs", "/dev/shm", "tmpfs", _usage(16, 12.0)),
            *[
                _mount("overlay", f"/run/containerd/task/{i}/rootfs", "overlay", {})
                for i in range(UNREADABLE_MOUNTS)
            ],
        ]
    }


def memory_payload(swap_gib: int = 8) -> dict[str, Any]:
    swap = {"total": swap_gib * GIB, "used": 2 * GIB, "free": 6 * GIB, "percent": 25.0}
    return {
        "virtual": {
            "total": 64 * GIB,
            "available": 16 * GIB,
            "percent": 75.0,
            "used": 40 * GIB,
            "free": 2 * GIB,
            "cached": 20 * GIB,
        },
        "swap": (
            {**swap, "sin": 0, "sout": 4096}
            if swap_gib
            else {"total": 0, "used": 0, "free": 0, "percent": 0.0, "sin": 0, "sout": 0}
        ),
    }


def system_payload() -> dict[str, Any]:
    """Shaped like kai-server: 28 logical cores, no logged-in users."""
    return {
        "cpu_percent": 13.3,
        "memory": {
            "total": 31 * GIB,
            "available": 13 * GIB,
            "percent": 56.8,
            "used": 17 * GIB,
            "free": 2 * GIB,
        },
        "load_avg_1_5_15": [10.13, 12.58, 10.15],
        "boot_time_epoch": 1790303480,
        "uptime_seconds": 1127113.7,
        "logged_in_users": [],
    }


def cpu_payload() -> dict[str, Any]:
    cores = [0, 0, 6.7, 0, 3.4, 100, 9.7, 0, 3.3, 6.9, 10.0, 0]
    return {
        "percent": 7.9,
        "per_core_percent": cores,
        "logical_cores": len(cores),
        "physical_cores": 6,
        "load_avg_1_5_15": [10.13, 12.58, 10.15],
    }


def pressure_payload(used_percent: float = 77.84) -> dict[str, Any]:
    """Thresholds 80 and 85, as the server's defaults. The View draws these, not its config."""
    total = 500 * GIB
    used = int(total * used_percent / 100)
    warn, critical = int(total * 0.80), int(total * 0.85)
    status = "critical" if used_percent >= 85 else "warning" if used_percent >= 80 else "ok"
    return {
        "root": {
            "path": "/",
            "total_bytes": total,
            "free_bytes": total - used,
            "available_bytes": total - used,
            "reserved_bytes": 0,
            "pressure_used_bytes": used,
            "used_percent": used_percent,
            "status": status,
            "warn_percent": 80,
            "critical_percent": 85,
            "bytes_until_warn": warn - used,
            "bytes_until_critical": critical - used,
            "bytes_over_warn": max(0, used - warn),
            "bytes_over_critical": max(0, used - critical),
            "inodes_total": 33529856,
            "inodes_free": 30429098,
            "inodes_available": 30429098,
            "inodes_used_percent": 9.25,
        }
    }


def _nic(sent: int, recv: int, **counters: int) -> dict[str, Any]:
    zeroes = {"errin": 0, "errout": 0, "dropin": 0, "dropout": 0}
    return {
        "bytes_sent": sent,
        "bytes_recv": recv,
        "packets_sent": sent // 1000,
        "packets_recv": recv // 1000,
        **zeroes,
        **counters,
    }


def network_payload(dropout: int = 1359) -> dict[str, Any]:
    """Lifetime counters as on kai-server: drops that happened days ago, not now."""
    return {
        "total": _nic(4930 * GIB, 6148 * GIB, dropin=917, dropout=3242),
        "per_interface": {
            "enp1s0": _nic(968 * GIB, 360 * GIB, dropin=917),
            "flannel.1": _nic(0, 0, dropout=1883),
            "tailscale0": _nic(835 * GIB, 38 * GIB, dropout=dropout),
        },
        "filtering": {"mode": "default", "omitted": 142, "omitted_prefixes": ["veth"]},
        "counter_semantics": "cumulative since boot",
    }


UNREAD_NOTE = (
    "/proc/net/stat/nf_conntrack is not present, so insert_failed, drop and early_drop "
    "are UNREAD rather than zero. count and max above are real."
)


def conntrack_payload(totals: dict[str, int] | None = None) -> dict[str, Any]:
    """Default is kai-server: the stat file is absent, so the totals are unread."""
    return {
        "count": 3873,
        "max": 917504,
        "utilization": 0.0042,
        "cpus": 28 if totals else 0,
        "totals": totals or {},
        "notes": [] if totals else [UNREAD_NOTE],
    }


def _container(name: str, ready: bool, state: str, **detail: Any) -> dict[str, Any]:
    return {
        "name": name,
        "image": "registry.test/" + name,
        "ready": ready,
        "restart_count": detail.pop("restarts", 0),
        "state": state,
        "state_detail": {"type": state, **detail},
        "last_state": detail.pop("last", None),
    }


def pods_payload() -> dict[str, Any]:
    def pod(ns: str, name: str, phase: str, containers: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "namespace": ns,
            "pod": name,
            "phase": phase,
            "node": "kai-server",
            "restart_count": sum(c["restart_count"] for c in containers),
            "age": "2d1h",
            "reason": None,
            "message": None,
            "containers": containers,
            "init_containers": [],
        }

    crash = _container("api", False, "waiting", reason="CrashLoopBackOff", restarts=9)
    crash["last_state"] = {"type": "terminated", "reason": "OOMKilled", "exit_code": 137}
    flaky = _container("provisioner", True, "running", restarts=40)
    done = _container("helm", False, "terminated", reason="Completed", exit_code=0)
    return {
        "namespace": None,
        # Three pods returned of six: the hero counts what is drawn, never pod_count.
        "pods": [
            pod("apps", "api-7d9", "Running", [crash]),
            pod("kube-system", "helm-install-traefik", "Succeeded", [done]),
            pod("kube-system", "local-path-provisioner", "Running", [flaky]),
        ],
        "pod_count": 6,
        "returned_pod_count": 3,
        "errors": [],
    }


def workloads_payload() -> dict[str, Any]:
    def workload(kind: str, ns: str, name: str, desired: int, ready: int, updated: int) -> Any:
        return {
            "kind": kind,
            "namespace": ns,
            "name": name,
            "generation": 5,
            "observed_generation": 5,
            "spec_images": [{"container": name, "image": f"registry.test/{name}:abc"}],
            "desired_replicas": desired,
            "ready_replicas": ready,
            "updated_replicas": updated,
            "available_replicas": ready,
            "rollout_complete": desired == ready == updated,
            "conditions": [],
        }

    return {
        "namespace": None,
        "workloads": [
            workload("Deployment", "apps", "api", 3, 2, 1),
            workload("Deployment", "authelia", "authelia", 1, 1, 1),
            workload("StatefulSet", "db", "idle", 0, 0, 0),
        ],
        "workload_count": 150,
        "returned_workload_count": 3,
        "errors": [],
    }


def node_health_payload(disk_pressure: str = "False") -> dict[str, Any]:
    def cond(kind: str, status: str, reason: str, since: str) -> dict[str, Any]:
        return {"type": kind, "status": status, "reason": reason, "last_transition_age": since}

    return {
        "node": {
            "name": "kai-server",
            "age": "543d1h",
            "unschedulable": False,
            "taints": [],
            "capacity": {"cpu": "28", "memory": "32543264Ki", "pods": "180"},
            "allocatable": {"cpu": "26", "memory": "30446112Ki", "pods": "180"},
            "conditions": [
                cond("MemoryPressure", "False", "KubeletHasSufficientMemory", "73d"),
                cond("DiskPressure", disk_pressure, "KubeletHasDiskPressure", "3m"),
                cond("Ready", "True", "KubeletReady", "73d"),
            ],
        },
        "events": [
            {
                "type": "Warning",
                "reason": "EvictionThresholdMet",
                "message": "Attempting to reclaim ephemeral-storage",
                "count": 2,
                "object": {"kind": "Node", "name": "kai-server"},
                "age": "2m",
            },
            {
                "type": "Normal",
                "reason": "Started",
                "message": "Started container heartbeat",
                "count": 1,
                "object": {"kind": "Pod", "name": "gatus-heartbeat"},
                "age": "1m",
            },
        ],
        "event_count": 35,
        "returned_event_count": 2,
        "max_age_hours": 24,
        "errors": [],
    }


VIEW_FIXTURES: dict[str, Callable[[], dict[str, Any]]] = {
    "disk": disk_payload,
    "memory": memory_payload,
    "system": system_payload,
    "cpu": cpu_payload,
    "pressure": pressure_payload,
    "network": network_payload,
    "conntrack": conntrack_payload,
    "k3s-pods": pods_payload,
    "k3s-workloads": workloads_payload,
    "k3s-node-health": node_health_payload,
}


def _tool_result(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(payload)}],
        "structuredContent": payload,
    }


def _kind(uri: str) -> str:
    return uri.rsplit("/", 1)[1]


@pytest.fixture(scope="module")
def declared_views() -> dict[str, str]:
    """Declared view URI -> page HTML, read through a real client session.

    Runs before the browser starts: asyncio.run cannot nest inside Playwright's loop.
    """
    import node_stats_mcp.server as server

    async def read(module: ModuleType) -> dict[str, str]:
        async with create_connected_server_and_client_session(module.mcp._mcp_server) as client:
            uris = {
                u
                for t in (await client.list_tools()).tools
                if (u := ((t.meta or {}).get("ui") or {}).get("resourceUri"))
            }
            pages = {}
            for uri in sorted(uris):
                (content,) = (await client.read_resource(AnyUrl(uri))).contents
                assert isinstance(content, TextResourceContents)
                pages[uri] = content.text
            return pages

    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("NODE_STATS_DISK_WARN_PERCENT", "70")
        patch.setenv("NODE_STATS_DISK_CRITICAL_PERCENT", "90")
        pages = asyncio.run(read(importlib.reload(server)))
    importlib.reload(server)
    return pages


@pytest.fixture(scope="module")
def browser(declared_views: dict[str, str]) -> Iterator[Browser]:
    with sync_playwright() as playwright:
        chromium = playwright.chromium.launch()
        yield chromium
        chromium.close()


class Host:
    """The stand-in host page for one View, plus what the page did while it ran."""

    def __init__(self, context: BrowserContext) -> None:
        self.page: Page = context.new_page()
        self.errors: list[str] = []
        self.requests: list[str] = []
        self.page.on("pageerror", lambda e: self.errors.append(f"pageerror: {e}"))
        self.page.on(
            "console",
            lambda m: (
                self.errors.append(f"console.{m.type}: {m.text}") if m.type == "error" else None
            ),
        )
        self.page.on("request", lambda r: self.requests.append(r.url))
        context.route(
            HOST_URL,
            lambda route: route.fulfill(
                body=HOST_PAGE,
                content_type="text/html",
                headers={"Content-Security-Policy": HOST_CSP},
            ),
        )
        self.page.goto(HOST_URL)

    def load(
        self,
        html: str,
        host_context: dict[str, Any] | None = None,
        capabilities: dict[str, Any] | None = None,
    ) -> None:
        self.page.evaluate("ctx => { window.hostContext = ctx }", host_context or {})
        self.page.evaluate("caps => { window.hostCapabilities = caps }", capabilities or {})
        self.page.evaluate("html => window.loadView(html)", html)

    def wait_until(self, condition: Callable[[], bool], what: str, timeout_ms: int = 5000) -> None:
        """Poll from Python: the host's CSP forbids the string eval wait_for_function uses."""
        for _ in range(timeout_ms // 25):
            if condition():
                return
            self.page.wait_for_timeout(25)
        raise AssertionError(f"timed out waiting for {what}")

    def wait_initialized(self) -> None:
        self.wait_until(
            lambda: bool(self.sent("ui/notifications/initialized")), "ui/notifications/initialized"
        )

    def send(self, method: str, params: dict[str, Any] | None = None) -> None:
        self.page.evaluate("m => window.hostSend(m)", {"method": method, "params": params or {}})

    def result(self, payload: dict[str, Any]) -> None:
        self.send("ui/notifications/tool-result", _tool_result(payload))

    def sent(self, method: str) -> list[dict[str, Any]]:
        log: list[dict[str, Any]] = self.page.evaluate("window.log")
        return [m for m in log if m.get("method") == method]

    def tool_results(self, name: str, results: list[dict[str, Any]]) -> None:
        """Queue what the host answers to the View's `tools/call` for `name`, one per call."""
        self.page.evaluate("([n, r]) => { window.toolResults[n] = r }", [name, results])

    def ui(self, selector: str, **options: Any) -> Any:
        return self.page.frame_locator("#view").locator(selector, **options)


@pytest.fixture
def open_view(browser: Browser, declared_views: dict[str, str]) -> Iterator[Callable[..., Host]]:
    contexts: list[BrowserContext] = []
    hosts: list[Host] = []

    def open_(
        kind: str,
        *,
        scheme: str = "light",
        host_context: dict[str, Any] | None = None,
        capabilities: dict[str, Any] | None = None,
    ) -> Host:
        context = browser.new_context(color_scheme=scheme, viewport={"width": 700, "height": 900})  # type: ignore[arg-type]
        contexts.append(context)
        host = Host(context)
        hosts.append(host)
        uri = next(u for u in declared_views if _kind(u) == kind)
        host.load(declared_views[uri], host_context, capabilities)
        return host

    yield open_
    for host in hosts:
        # Nothing the View does may fail quietly: a refused fetch, a throw, a CSP report.
        assert host.errors == []
        assert host.requests == [HOST_URL]
    for context in contexts:
        context.close()


def test_every_declared_view_has_a_fixture(declared_views: dict[str, str]) -> None:
    kinds = {_kind(u) for u in declared_views}
    assert kinds == set(VIEW_FIXTURES), (
        f"views {sorted(kinds - set(VIEW_FIXTURES))} declare a ui:// resource but have no "
        f"entry in VIEW_FIXTURES, and fixtures {sorted(set(VIEW_FIXTURES) - kinds)} have no view"
    )


@pytest.mark.parametrize("kind", sorted(VIEW_FIXTURES))
def test_handshake_then_draw_with_a_table_view(open_view: Callable[..., Host], kind: str) -> None:
    host = open_view(kind)

    # Before the result arrives the View waits and draws nothing.
    expect(host.ui("#status")).to_have_text("Waiting for the tool result.")
    expect(host.ui("#view")).to_be_hidden()
    host.wait_initialized()

    methods = [m["method"] for m in host.page.evaluate("window.log") if "method" in m]
    assert methods[:2] == ["ui/initialize", "ui/notifications/initialized"]
    (init,) = host.sent("ui/initialize")
    assert init["params"]["protocolVersion"] == PROTOCOL_VERSION
    assert init["params"]["appInfo"]["name"] == f"node-stats-{kind}"
    assert "id" not in host.sent("ui/notifications/initialized")[0]

    host.result(VIEW_FIXTURES[kind]())
    expect(host.ui("#view")).to_be_visible()
    expect(host.ui("#status")).to_be_hidden()
    expect(host.ui("details > summary")).to_have_text("Table view")
    expect(host.ui("details table tbody tr").first).to_be_attached()


def test_disk_draws_one_row_per_filesystem_fullest_first(
    open_view: Callable[..., Host],
) -> None:
    host = open_view("disk")
    host.wait_initialized()
    host.result(disk_payload())

    rows = host.ui(".row")
    # Four entries carry usage, two of them one device with identical numbers.
    expect(rows).to_have_count(CHARTED_ENTRIES - 1)
    expect(host.ui("#title")).to_have_text("Disk usage")
    expect(host.ui(".hero b")).to_have_text("93.0%")
    expect(host.ui(".hero span")).to_have_text("of the fullest filesystem used, /dev/sdb1")
    expect(rows.nth(0).locator(".name")).to_have_text("/dev/sdb1")
    expect(rows.nth(1).locator(".name")).to_have_text("/dev/nvme0n1p2")
    expect(rows.nth(1).locator(".sub")).to_have_text("ext4 at / and 1 more")
    expect(rows.nth(2).locator(".name")).to_have_text("tmpfs")
    expect(host.ui("details table tbody tr")).to_have_count(CHARTED_ENTRIES - 1)


def test_disk_counts_mounts_with_no_usage_instead_of_drawing_them(
    open_view: Callable[..., Host],
) -> None:
    host = open_view("disk")
    host.wait_initialized()
    host.result(disk_payload())

    total = CHARTED_ENTRIES + UNREADABLE_MOUNTS
    expect(host.ui(".note").last).to_have_text(
        f"{UNREADABLE_MOUNTS} of {total} mounts reported no usage and are not charted. "
        "The text result lists them."
    )
    expect(host.ui(".row", has_text="overlay")).to_have_count(0)


def test_disk_flags_critical_and_warning_and_leaves_the_rest_plain(
    open_view: Callable[..., Host],
) -> None:
    host = open_view("disk")
    host.wait_initialized()
    host.result(disk_payload())

    rows = host.ui(".row")
    expect(rows.nth(0).locator(".flag")).to_have_text("✕ Critical: at or above 90%")
    expect(rows.nth(0).locator(".fill")).to_have_class("fill crit")
    expect(rows.nth(1).locator(".flag")).to_have_text("▲ Warning: at or above 70%")
    expect(rows.nth(1).locator(".fill")).to_have_class("fill warn")
    expect(rows.nth(2).locator(".flag")).to_have_count(0)
    expect(rows.nth(2).locator(".fill")).to_have_class("fill")
    # The ticks sit at the thresholds the server baked into the page.
    ticks = rows.nth(0).locator(".tick")
    expect(ticks.nth(0)).to_have_attribute("style", "left: 70%")
    expect(ticks.nth(1)).to_have_attribute("style", "left: 90%")
    expect(host.ui(".note").first).to_have_text(
        "Ticks mark the warning (70%) and critical (90%) thresholds."
    )


def test_disk_with_no_usage_anywhere_says_so(open_view: Callable[..., Host]) -> None:
    host = open_view("disk")
    host.wait_initialized()
    host.result({"partitions": [_mount("overlay", "/a", "overlay", {})]})

    expect(host.ui(".row")).to_have_count(0)
    expect(host.ui(".note").first).to_have_text(
        "No mount reported usage, so there is nothing to chart."
    )


def test_memory_stacks_in_use_against_available_and_swap(
    open_view: Callable[..., Host],
) -> None:
    host = open_view("memory")
    host.wait_initialized()
    host.result(memory_payload())

    expect(host.ui("#title")).to_have_text("Memory usage")
    expect(host.ui(".hero b")).to_have_text("75.0%")
    expect(host.ui(".hero span")).to_have_text("of 64.0 GiB memory in use")
    rows = host.ui(".row")
    expect(rows).to_have_count(2)
    # In use is total minus available (48 GiB), not psutil's own `used` (40 GiB).
    expect(rows.nth(0).locator(".value")).to_have_text("75.0% // 48.0 GiB of 64.0 GiB")
    expect(rows.nth(1).locator(".value")).to_have_text("25.0% // 2.0 GiB of 8.0 GiB")
    expect(host.ui("details table tbody tr", has_text="memory cached")).to_contain_text("20.0 GiB")
    expect(host.ui("details table tbody tr", has_text="swap sout")).to_contain_text("cumulative")


def test_memory_without_swap_says_none_is_configured(open_view: Callable[..., Host]) -> None:
    host = open_view("memory")
    host.wait_initialized()
    host.result(memory_payload(swap_gib=0))

    expect(host.ui(".row")).to_have_count(1)
    expect(host.ui(".note").first).to_have_text("No swap is configured.")


def test_reads_the_text_block_when_there_is_no_structured_content(
    open_view: Callable[..., Host],
) -> None:
    host = open_view("memory")
    host.wait_initialized()
    host.send(
        "ui/notifications/tool-result",
        {"content": [{"type": "text", "text": json.dumps(memory_payload())}]},
    )

    expect(host.ui(".hero b")).to_have_text("75.0%")


@pytest.mark.parametrize(
    ("result", "message"),
    [
        (
            {"isError": True, "content": [{"type": "text", "text": "boom"}]},
            "The tool returned an error. The text result has the detail.",
        ),
        (
            {"content": [{"type": "text", "text": "not json"}]},
            "This view could not read the tool result. The text result is unchanged.",
        ),
    ],
)
def test_an_unusable_result_leaves_a_message_not_a_blank_frame(
    open_view: Callable[..., Host], result: dict[str, Any], message: str
) -> None:
    host = open_view("disk")
    host.wait_initialized()
    host.send("ui/notifications/tool-result", result)

    expect(host.ui("#status")).to_have_text(message)
    expect(host.ui("#view")).to_be_hidden()


def test_a_cancelled_tool_call_replaces_the_drawing_with_a_message(
    open_view: Callable[..., Host],
) -> None:
    host = open_view("disk")
    host.wait_initialized()
    host.result(disk_payload())
    expect(host.ui("#view")).to_be_visible()
    host.send("ui/notifications/tool-cancelled")

    expect(host.ui("#status")).to_have_text("The tool call was cancelled.")
    expect(host.ui("#view")).to_be_hidden()


def test_a_second_result_redraws_in_place(open_view: Callable[..., Host]) -> None:
    host = open_view("disk")
    host.wait_initialized()
    host.result(disk_payload())
    expect(host.ui(".row")).to_have_count(3)
    host.result({"partitions": [_mount("/dev/sdb1", "/mnt/data", "xfs", _usage(2000, 50.0))]})

    expect(host.ui(".row")).to_have_count(1)
    expect(host.ui(".flag")).to_have_count(0)


@pytest.mark.parametrize("kind", sorted(VIEW_FIXTURES))
@pytest.mark.parametrize(
    ("scheme", "host_theme", "expected"),
    [
        # Surface colors are the View's own tokens: light #fcfcfb, dark #1a1a19.
        ("light", "dark", "rgb(26, 26, 25)"),
        ("dark", "light", "rgb(252, 252, 251)"),
        ("dark", None, "rgb(26, 26, 25)"),
        ("light", None, "rgb(252, 252, 251)"),
    ],
)
def test_theme_follows_the_host_and_falls_back_to_the_os_scheme(
    open_view: Callable[..., Host], kind: str, scheme: str, host_theme: str | None, expected: str
) -> None:
    host = open_view(kind, scheme=scheme, host_context={"theme": host_theme} if host_theme else {})
    host.wait_initialized()
    host.result(VIEW_FIXTURES[kind]())

    expect(host.ui("body")).to_have_css("background-color", expected)


def test_a_host_theme_change_after_the_handshake_is_applied(
    open_view: Callable[..., Host],
) -> None:
    host = open_view("disk", host_context={"theme": "light"})
    host.wait_initialized()
    host.result(disk_payload())
    expect(host.ui("body")).to_have_css("background-color", "rgb(252, 252, 251)")
    host.send("ui/notifications/host-context-changed", {"theme": "dark"})

    expect(host.ui("body")).to_have_css("background-color", "rgb(26, 26, 25)")


def test_size_changed_reports_the_frame_width_and_grows_with_the_content(
    open_view: Callable[..., Host],
) -> None:
    host = open_view("disk")
    host.wait_initialized()
    host.wait_until(lambda: bool(host.sent("ui/notifications/size-changed")), "first size-changed")
    seen = len(host.sent("ui/notifications/size-changed"))
    before = host.sent("ui/notifications/size-changed")[-1]["params"]
    host.result(disk_payload())
    host.wait_until(
        lambda: len(host.sent("ui/notifications/size-changed")) > seen, "size-changed after result"
    )
    after = host.sent("ui/notifications/size-changed")[-1]["params"]

    assert before["width"] == after["width"] == 600
    assert 0 < before["height"] < after["height"]


def test_ping_and_teardown_requests_are_answered(open_view: Callable[..., Host]) -> None:
    host = open_view("memory")
    host.wait_initialized()
    host.page.evaluate("window.hostSend({ id: 91, method: 'ping' })")
    host.page.evaluate("window.hostSend({ id: 92, method: 'ui/resource-teardown', params: {} })")

    answered = lambda: {m.get("id") for m in host.page.evaluate("window.log") if "result" in m}  # noqa: E731
    host.wait_until(lambda: {91, 92} <= answered(), "ping and teardown answers")


def test_host_answers_tools_call_from_the_view_in_queue_order(
    open_view: Callable[..., Host],
) -> None:
    """The seam for views that resample a counter: the View asks, the host answers."""
    host = open_view("memory")
    host.wait_initialized()
    first, second = _tool_result({"n": 1}), _tool_result({"n": 2})
    host.tool_results("get_network_info", [first, second])
    ask = """(name) => new Promise((resolve) => {
      const id = Math.floor(Math.random() * 1e9);
      window.addEventListener("message", function on(e) {
        if (!e.data || e.data.id !== id) return;
        window.removeEventListener("message", on);
        resolve(e.data);
      });
      window.parent.postMessage({ jsonrpc: "2.0", id, method: "tools/call",
        params: { name, arguments: {} } }, "*");
    })"""
    frame = host.page.query_selector("#view").content_frame()  # type: ignore[union-attr]
    assert frame is not None

    assert frame.evaluate(ask, "get_network_info")["result"] == first
    assert frame.evaluate(ask, "get_network_info")["result"] == second
    assert "no result queued" in frame.evaluate(ask, "get_network_info")["error"]["message"]
    assert [c["params"]["name"] for c in host.sent("tools/call")] == ["get_network_info"] * 3


def test_pressure_draws_the_thresholds_the_result_carries_not_the_page_config(
    open_view: Callable[..., Host],
) -> None:
    # The page config says 70/90 (see declared_views). The result says 80/85 and wins.
    host = open_view("pressure")
    host.wait_initialized()
    host.result(pressure_payload(used_percent=82.0))

    ticks = host.ui(".bar .tick")
    expect(ticks).to_have_count(2)
    expect(ticks.nth(0)).to_have_attribute("style", "left: 80%")
    expect(ticks.nth(1)).to_have_attribute("style", "left: 85%")
    expect(host.ui(".flag")).to_have_text("▲ Warning: at or above 80%")
    expect(host.ui(".items li").nth(0)).to_contain_text("over warning (80%)")
    expect(host.ui(".items li").nth(1)).to_contain_text("until critical (85%)")


def test_pressure_below_the_warning_threshold_draws_no_flag(
    open_view: Callable[..., Host],
) -> None:
    host = open_view("pressure")
    host.wait_initialized()
    host.result(pressure_payload())

    expect(host.ui(".flag")).to_have_count(0)
    expect(host.ui(".items li").nth(0)).to_contain_text("until warning (80%)")


def test_pods_count_the_rows_drawn_and_name_why_the_broken_one_is_broken(
    open_view: Callable[..., Host],
) -> None:
    host = open_view("k3s-pods")
    host.wait_initialized()
    host.result(pods_payload())

    # pod_count is 6 and three rows came back. The hero must not claim "of 6".
    expect(host.ui(".hero b")).to_have_text("2 of 3")
    attention = host.ui(".items li")
    expect(attention).to_have_count(1)
    expect(attention).to_contain_text("apps/api-7d9")
    expect(attention).to_contain_text("CrashLoopBackOff; last OOMKilled exit 137, 9 restarts")
    expect(host.ui(".note", has_text="Showing 3 of 6 pods")).to_have_count(1)
    expect(host.ui(".note", has_text="Restarted but healthy now")).to_contain_text("(40)")


def test_workloads_flag_only_the_incomplete_rollout(open_view: Callable[..., Host]) -> None:
    host = open_view("k3s-workloads")
    host.wait_initialized()
    host.result(workloads_payload())

    expect(host.ui(".hero b")).to_have_text("2 of 3")
    expect(host.ui(".flag")).to_have_count(1)
    expect(host.ui(".flag")).to_contain_text("Rollout incomplete: 1 of 3 updated")
    expect(host.ui(".row", has_text="idle")).to_contain_text("scaled to 0")


def test_node_conditions_read_true_as_healthy_only_for_ready(
    open_view: Callable[..., Host],
) -> None:
    host = open_view("k3s-node-health")
    host.wait_initialized()
    host.result(node_health_payload(disk_pressure="True"))

    expect(host.ui(".hero b")).to_have_text("Ready")
    expect(host.ui(".hero span")).to_contain_text("1 condition needs attention")
    bad = host.ui(".items li.bad")
    expect(bad).to_have_count(1)
    expect(bad).to_contain_text("✕ DiskPressure: True")
    expect(host.ui(".items li", has_text="✓ Ready: True")).to_have_count(1)
    expect(host.ui(".items li", has_text="✓ MemoryPressure: False")).to_have_count(1)
    expect(host.ui("details table")).to_have_count(3)


def test_node_with_every_condition_clear_says_so(open_view: Callable[..., Host]) -> None:
    host = open_view("k3s-node-health")
    host.wait_initialized()
    host.result(node_health_payload())

    expect(host.ui(".hero span")).to_contain_text("no condition needs attention")
    expect(host.ui(".items li.bad")).to_have_count(0)


def test_conntrack_with_unread_totals_prints_the_note_and_offers_no_movement(
    open_view: Callable[..., Host],
) -> None:
    host = open_view("conntrack", capabilities={"serverTools": {}})
    host.wait_initialized()
    host.result(conntrack_payload())

    # A movement panel here would read "nothing moved" about counters nobody read.
    expect(host.ui(".flag")).to_contain_text("UNREAD rather than zero")
    expect(host.ui(".live")).to_have_count(0)


def test_a_host_without_server_tools_is_told_to_call_the_tool_twice(
    open_view: Callable[..., Host],
) -> None:
    host = open_view("network")
    host.wait_initialized()
    host.result(network_payload())

    expect(host.ui(".live")).to_contain_text("does not proxy tool calls")
    expect(host.ui(".live button")).to_have_count(0)


def test_watching_asks_the_host_for_the_same_tool_and_names_a_counter_that_moved(
    open_view: Callable[..., Host],
) -> None:
    host = open_view("network", capabilities={"serverTools": {}})
    host.wait_initialized()
    host.send("ui/notifications/tool-input", {"arguments": {"interfaces": "all"}})
    host.tool_results("get_network_info", [_tool_result(network_payload(dropout=1366))])
    host.result(network_payload())

    expect(host.ui(".live")).to_contain_text("Counters are cumulative")
    host.ui(".live button", has_text="Watch movement").click()

    expect(host.ui(".live .moved")).to_have_text(
        "▲ Moved since the first reading: dropout +7", timeout=5000
    )
    (call,) = host.sent("tools/call")
    assert call["params"] == {"name": "get_network_info", "arguments": {"interfaces": "all"}}
    expect(host.ui(".live .row", has_text="enp1s0")).to_contain_text(
        "No error or drop counter has moved"
    )
    host.ui(".live button", has_text="Stop").click()
    expect(host.ui(".live button", has_text="Watch movement")).to_be_visible()


def test_a_counter_that_goes_backward_is_a_reset_not_negative_movement(
    open_view: Callable[..., Host],
) -> None:
    host = open_view("network", capabilities={"serverTools": {}})
    host.wait_initialized()
    host.tool_results("get_network_info", [_tool_result(network_payload(dropout=3))])
    host.result(network_payload())

    host.ui(".live button", has_text="Watch movement").click()

    expect(host.ui(".live .row", has_text="tailscale0")).to_contain_text(
        "No error or drop counter has moved", timeout=5000
    )
    host.ui(".live button", has_text="Stop").click()


def test_a_refused_second_reading_is_reported_and_stops_the_watch(
    open_view: Callable[..., Host],
) -> None:
    host = open_view("network", capabilities={"serverTools": {}})
    host.wait_initialized()
    host.result(network_payload())

    # Nothing queued for get_network_info, so the host answers with an error.
    host.ui(".live button", has_text="Watch movement").click()

    expect(host.ui(".live .note").first).to_contain_text(
        "The host refused a second reading", timeout=5000
    )
    expect(host.ui(".live button", has_text="Watch movement")).to_be_visible()
