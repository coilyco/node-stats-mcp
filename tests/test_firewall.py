"""Tests for the read-only ufw reader (COI-2699).

The fixtures follow ufw 0.36's own `### tuple ###` encoding. docs/tools-firewall.md
names the source, and why a config read cannot confirm the kernel chains.
"""

from __future__ import annotations

import ast
import asyncio
import importlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from node_stats_mcp import firewall

UFW_CONF_OFF = "# comment\nENABLED=no\nLOGLEVEL=low\n"
UFW_CONF_ON = "ENABLED=yes\nLOGLEVEL=low\n"
DEFAULTS = (
    "# /etc/default/ufw\nIPV6=yes\n"
    'DEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n'
    'DEFAULT_FORWARD_POLICY="DROP"\nDEFAULT_APPLICATION_POLICY="SKIP"\n'
)

USER_RULES = """*filter
:ufw-user-input - [0:0]
### RULES ###

### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 22 -j ACCEPT

### tuple ### allow tcp 9100 0.0.0.0/0 any 100.64.0.0/10 in_tailscale0
-A ufw-user-input -i tailscale0 -p tcp --dport 9100 -s 100.64.0.0/10 -j ACCEPT

### tuple ### deny tcp 8089 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 8089 -j DROP

### tuple ### allow tcp 8089 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 8089 -j ACCEPT

### tuple ### allow tcp 80,443 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp -m multiport --dports 80,443 -j ACCEPT

### tuple ### limit_log-all tcp 6000:6010 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp -m multiport --dports 6000:6010 -j ufw-user-limit

### END RULES ###
"""

USER6_RULES = """### RULES ###

### tuple ### allow tcp 22 ::/0 any ::/0 in
-A ufw6-user-input -p tcp --dport 22 -j ACCEPT

### tuple ### deny tcp 3389 ::/0 any ::/0 in
-A ufw6-user-input -p tcp --dport 3389 -j DROP

### END RULES ###
"""


def _host(
    tmp_path: Path,
    *,
    conf: str | None = UFW_CONF_ON,
    defaults: str | None = DEFAULTS,
    v4: str | None = USER_RULES,
    v6: str | None = USER6_RULES,
) -> str:
    files = {
        "etc/ufw/ufw.conf": conf,
        "etc/default/ufw": defaults,
        "etc/ufw/user.rules": v4,
        "etc/ufw/user6.rules": v6,
    }
    for name, text in files.items():
        if text is None:
            continue
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return str(tmp_path)


def _listener(port: int, *, family: str = "v4", address: str = "0.0.0.0", protocol: str = "tcp"):
    return {"protocol": protocol, "family": family, "address": address, "port": port}


def _verdicts(result: dict[str, Any]) -> dict[tuple[str, int], dict[str, Any]]:
    return {(item["family"], item["port"]): item for item in result["listeners"]}


def test_parse_tuple_reads_a_plain_input_rule() -> None:
    rule = firewall.parse_tuple("### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in")

    assert rule["action"] == "allow"
    assert rule["protocol"] == "tcp"
    assert rule["dport"] == "22"
    assert rule["direction"] == "in"
    assert rule["interface_in"] is None
    assert rule["summary"] == "allow in tcp/22 from 0.0.0.0/0"


def test_parse_tuple_reads_interface_log_route_app_and_comment() -> None:
    rule = firewall.parse_tuple(
        "### tuple ### route:allow_log tcp 80 10.0.0.0/8 any 0.0.0.0/0 OpenSSH%20Full - "
        "in_eth0!out_cni0 comment=" + b"ssh from lan".hex()
    )

    assert rule["route"] is True
    assert rule["action"] == "allow"
    assert rule["log"] == "log"
    assert rule["interface_in"] == "eth0"
    assert rule["interface_out"] == "cni0"
    assert rule["dst_app"] == "OpenSSH%20Full"
    assert rule["src_app"] is None
    assert rule["comment"] == "ssh from lan"


def test_parse_tuple_without_a_direction_defaults_to_input() -> None:
    rule = firewall.parse_tuple("### tuple ### deny udp 53 0.0.0.0/0 any 0.0.0.0/0")

    assert rule["direction"] == "in"
    assert rule["interface_in"] is None


@pytest.mark.parametrize(
    "line",
    [
        "### tuple ### allow tcp 22",
        "### tuple ### allow tcp http 0.0.0.0/0 any 0.0.0.0/0 in",
        "### tuple ### a b c d e f g h i j",
    ],
)
def test_parse_tuple_rejects_a_line_without_ufws_shape(line: str) -> None:
    with pytest.raises(ValueError):
        firewall.parse_tuple(line)


def test_unparsed_tuples_are_counted_and_surface_in_the_notes(tmp_path: Path) -> None:
    broken = USER_RULES + "### tuple ### allow tcp\n"

    result = firewall.snapshot(_host(tmp_path, v4=broken), [], [])

    assert result["unparsed_tuples"] == {"v4": 1, "v6": 0}
    assert any("did not parse" in note for note in result["notes"])
    assert result["rule_counts"]["v4"] == 6


def test_inactive_ufw_reads_as_inactive_and_still_lists_the_rules(tmp_path: Path) -> None:
    """The state both hosts were observed in: ENABLED=no with rules on disk."""
    listeners = [
        _listener(22),
        _listener(22, family="v6", address="::"),
        _listener(5432, address="127.0.0.1"),
    ]

    result = firewall.snapshot(_host(tmp_path, conf=UFW_CONF_OFF), listeners, [])

    assert result["status"] == "inactive"
    assert result["enabled_in_config"] is False
    assert result["kernel_chains_verified"] is False
    assert result["status_verbose_header"] == ["Status: inactive"]
    assert result["default_policy"] == {"incoming": "deny", "outgoing": "allow", "routed": "deny"}
    assert result["rule_counts"] == {"v4": 6, "v6": 2}
    verdicts = _verdicts(result)
    assert verdicts[("v4", 22)]["verdict"] == "not_filtered_by_ufw"
    assert verdicts[("v6", 22)]["verdict"] == "not_filtered_by_ufw"
    assert verdicts[("v4", 5432)]["verdict"] == "loopback_only"
    assert any("not filtering" in note for note in result["notes"])


def test_enabled_ufw_reports_the_header_and_what_it_cannot_confirm(tmp_path: Path) -> None:
    result = firewall.snapshot(_host(tmp_path), [], [])

    assert result["status"] == "enabled_in_config"
    assert result["status_verbose_header"] == [
        "Status: active",
        "Logging: on (low)",
        "Default: deny (incoming), allow (outgoing), deny (routed)",
        "New profiles: skip",
    ]
    assert any("CAP_NET_ADMIN" in note for note in result["notes"])


def test_listener_verdicts_follow_rule_order_default_policy_and_restrictions(
    tmp_path: Path,
) -> None:
    listeners = [
        _listener(22),
        _listener(22, family="v6", address="::"),
        _listener(3389, family="v6", address="::"),
        _listener(6443),
        _listener(9100),
        _listener(8089),
        _listener(443),
        _listener(6005),
    ]

    verdicts = _verdicts(firewall.snapshot(_host(tmp_path), listeners, []))

    assert verdicts[("v4", 22)]["verdict"] == "allow"
    assert verdicts[("v4", 22)]["decided_by"] == "rule #1"
    assert verdicts[("v6", 22)]["verdict"] == "allow"
    assert verdicts[("v6", 3389)]["verdict"] == "deny"
    assert verdicts[("v4", 6443)]["verdict"] == "deny"
    assert verdicts[("v4", 6443)]["decided_by"] == "default incoming policy"
    # Only the tailnet may reach 9100, so everyone else falls to the default.
    assert verdicts[("v4", 9100)]["verdict"] == "deny"
    assert verdicts[("v4", 9100)]["restricted_rules"] == [
        "#2 allow in on tailscale0 tcp/9100 from 100.64.0.0/10"
    ]
    # The deny precedes the allow for 8089, and the first match wins.
    assert verdicts[("v4", 8089)]["verdict"] == "deny"
    assert verdicts[("v4", 8089)]["decided_by"] == "rule #3"
    assert verdicts[("v4", 443)]["verdict"] == "allow"
    assert verdicts[("v4", 6005)]["verdict"] == "allow"


def test_a_udp_listener_is_not_covered_by_a_tcp_rule(tmp_path: Path) -> None:
    listeners = [_listener(22, protocol="udp"), _listener(22)]

    result = firewall.snapshot(_host(tmp_path), listeners, [])

    by_protocol = {item["protocol"]: item["verdict"] for item in result["listeners"]}
    assert by_protocol == {"udp": "deny", "tcp": "allow"}


def test_a_rule_to_one_address_does_not_cover_a_wildcard_listener(tmp_path: Path) -> None:
    rules = "### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in\n"
    scoped = "### tuple ### allow tcp 81 192.168.1.5 any 0.0.0.0/0 in\n"
    host = _host(tmp_path, v4=rules + scoped)

    result = firewall.snapshot(
        host,
        [_listener(81), _listener(81, address="192.168.1.5"), _listener(80)],
        [],
    )

    by_address = {(item["port"], item["address"]): item for item in result["listeners"]}
    assert by_address[(81, "0.0.0.0")]["verdict"] == "deny"
    assert by_address[(81, "0.0.0.0")]["restricted_rules"]
    assert by_address[(81, "192.168.1.5")]["verdict"] == "allow"
    assert by_address[(80, "0.0.0.0")]["verdict"] == "allow"


def test_ipv6_unmanaged_means_v6_listeners_are_not_filtered(tmp_path: Path) -> None:
    host = _host(tmp_path, defaults=DEFAULTS.replace("IPV6=yes", "IPV6=no"))

    result = firewall.snapshot(host, [_listener(22), _listener(22, family="v6", address="::")], [])

    verdicts = _verdicts(result)
    assert result["ipv6_managed"] is False
    assert verdicts[("v4", 22)]["verdict"] == "allow"
    assert verdicts[("v6", 22)]["verdict"] == "not_filtered_by_ufw"
    assert "IPV6=no" in verdicts[("v6", 22)]["decided_by"]


def test_absent_ufw_is_unknown_and_says_it_is_not_installed(tmp_path: Path) -> None:
    result = firewall.snapshot(
        _host(tmp_path, conf=None, defaults=None, v4=None, v6=None), [_listener(22)], []
    )

    assert result["status"] == "unknown"
    assert result["enabled_in_config"] is None
    assert result["listeners"][0]["verdict"] == "unknown"
    assert any("not installed" in note for note in result["notes"])


def test_unreadable_rules_are_missing_not_empty(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    host = _host(tmp_path)
    real_open = Path.open

    def deny_rules(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.name.startswith("user"):
            raise PermissionError(13, "Permission denied")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_rules)

    result = firewall.snapshot(host, [], [])

    assert result["sources"]["rules_v4"] == {
        "path": "/etc/ufw/user.rules",
        "readable": False,
        "reason": "permission denied",
    }
    assert result["rule_counts"] == {"v4": 0, "v6": 0}
    assert any("missing, not empty" in note for note in result["notes"])


def test_a_directory_where_a_file_belongs_is_reported_not_raised(tmp_path: Path) -> None:
    host = _host(tmp_path)
    (tmp_path / "etc/ufw/user.rules").unlink()
    (tmp_path / "etc/ufw/user.rules").mkdir()

    result = firewall.snapshot(host, [], [])

    assert result["sources"]["rules_v4"]["readable"] is False
    assert result["sources"]["rules_v4"]["reason"].startswith("unreadable")


def test_limit_caps_rules_and_listeners_but_counts_stay_true(tmp_path: Path) -> None:
    listeners = [_listener(port) for port in range(1000, 1010)]

    result = firewall.snapshot(_host(tmp_path), listeners, [], limit=3)

    assert len(result["rules"]["v4"]) == 3
    assert result["rule_counts"]["v4"] == 6
    assert result["rules_truncated"] == {"v4": True, "v6": False}
    assert len(result["listeners"]) == 3
    assert any("truncated to 3 of 10" in note for note in result["notes"])


def test_the_file_read_is_bounded(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(firewall, "MAX_FILE_BYTES", 64)
    host = _host(tmp_path, v4="### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n" * 50)

    result = firewall.snapshot(host, [], [])

    assert result["sources"]["rules_v4"]["truncated"] is True
    assert result["rule_counts"]["v4"] <= 2


def test_the_module_has_no_way_to_run_a_command_or_write_a_file() -> None:
    tree = ast.parse(Path(firewall.__file__).read_text())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])

    assert imported.isdisjoint({"subprocess", "os", "shutil", "socket", "ctypes", "pty"})
    opens = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"write_text", "write_bytes", "unlink", "chmod", "mkdir", "touch"}
    ]
    assert opens == []


# --- the registered tool ----------------------------------------------------


def _load_server(monkeypatch: pytest.MonkeyPatch, rootfs: str) -> Any:
    monkeypatch.setenv("ROOTFS", rootfs)
    monkeypatch.setenv("NODE_STATS_READABLE_ROOTS", "")
    import node_stats_mcp.server as server

    return importlib.reload(server)


def _conn(kind: str, family: str, ip: str, port: int, status: str, remote: Any = ()) -> Any:
    import socket

    return SimpleNamespace(
        family=socket.AF_INET6 if family == "v6" else socket.AF_INET,
        type=socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM,
        laddr=SimpleNamespace(ip=ip, port=port),
        raddr=remote,
        status=status,
    )


def test_the_tool_is_registered_and_builds_listeners_from_listening_sockets_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = _load_server(monkeypatch, _host(tmp_path, conf=UFW_CONF_OFF))
    connections = [
        _conn("tcp", "v4", "0.0.0.0", 22, "LISTEN"),
        _conn("tcp", "v4", "0.0.0.0", 22, "LISTEN"),
        _conn("tcp", "v6", "::", 22, "LISTEN"),
        _conn("tcp", "v4", "10.0.0.2", 22, "ESTABLISHED", remote=SimpleNamespace(ip="1.1.1.1")),
        _conn("udp", "v4", "0.0.0.0", 5353, "NONE"),
        _conn("udp", "v4", "10.0.0.2", 40000, "NONE", remote=SimpleNamespace(ip="1.1.1.1")),
    ]
    monkeypatch.setattr(server.psutil, "net_connections", lambda kind: connections)

    result = asyncio.run(server.get_host_firewall())

    seen = [(i["protocol"], i["family"], i["port"]) for i in result["listeners"]]
    assert seen == [("tcp", "v4", 22), ("tcp", "v6", 22), ("udp", "v4", 5353)]
    names = {tool.name for tool in asyncio.run(server.mcp.list_tools())}
    assert "get_host_firewall" in names


def test_a_denied_socket_walk_still_returns_the_ufw_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = _load_server(monkeypatch, _host(tmp_path, conf=UFW_CONF_OFF))

    def deny(kind: str) -> list[Any]:
        raise PermissionError

    monkeypatch.setattr(server.psutil, "net_connections", deny)

    result = asyncio.run(server.get_host_firewall())

    assert result["status"] == "inactive"
    assert result["listeners"] == []
    assert any("denied" in note for note in result["notes"])
