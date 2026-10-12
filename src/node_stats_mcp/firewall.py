"""Read-only ufw state, taken from ufw's own config files and a host-written snapshot.

The module reads five fixed files under ROOTFS and opens nothing a caller names.
It cannot change a rule: there is no write path and no subprocess. Live netfilter
needs CAP_NET_ADMIN, which the pod does not hold, so the kernel half comes from a
root timer's dump of `ufw status verbose` and `nft list ruleset` (COI-2704).
`kernel_chains_verified` is True only for a fresh dump that shows ufw active with
its chains loaded. See docs/tools-firewall.md.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

UFW_CONF = "/etc/ufw/ufw.conf"
UFW_DEFAULTS = "/etc/default/ufw"
UFW_RULES = {"v4": "/etc/ufw/user.rules", "v6": "/etc/ufw/user6.rules"}
# Written every 5 min by the host-firewall-snapshot timer in infrastructure.
SNAPSHOT_PATH = "/var/lib/host-firewall-snapshot/state.txt"
# Three missed runs. Older than this and the dump says nothing about now.
STALE_AFTER_SECONDS = 900
# The dump carries the whole nft ruleset, which kube-proxy makes large.
MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024

# The rules files are a few KB. The cap only stops a wrong file from streaming.
MAX_FILE_BYTES = 262144
MAX_COMMENT_CHARS = 120
DEFAULT_LIMIT = 100
MAX_LIMIT = 500

_ANY_ADDRESSES = {"0.0.0.0/0", "::/0", "any", "anywhere"}
_WILDCARD_BINDS = {"0.0.0.0", "::"}
_DIRECTION_RE = re.compile(r"^(in|out)([_!]|$)")
_POLICY_WORDS = {"accept": "allow", "reject": "reject"}
_KEY_VALUE_RE = re.compile(r'^\s*(\w+)\s*=\s*"?([^"#\s]*)"?')
_HEX_RE = re.compile(r"^(?:[0-9a-f]{2})+$")
_SNAPSHOT_HEADER_RE = re.compile(r"^# host-firewall-snapshot (\S+) host=(\S+)\s*$")
_UFW_STATUS_RE = re.compile(r"^Status:\s*(active|inactive)\s*$", re.MULTILINE)
_COMMAND_EXIT_RE = re.compile(r"^(ufw|nft) exited (\d+)\s*$", re.MULTILINE)
_UFW_CHAIN_RE = re.compile(r"^\s*chain (ufw6?-user-input)\b", re.MULTILINE)


def _read_file(rootfs: str, path: str, max_bytes: int | None = None) -> dict[str, Any]:
    """Read one fixed file, bounded, reporting why it is absent rather than empty."""
    cap = max_bytes or MAX_FILE_BYTES
    target = Path(rootfs).joinpath(path.lstrip("/"))
    source: dict[str, Any] = {"path": path, "readable": False}
    try:
        with target.open("rb") as handle:
            data = handle.read(cap + 1)
        mtime = target.stat().st_mtime
    except FileNotFoundError:
        source["reason"] = "absent"
    except PermissionError:
        source["reason"] = "permission denied"
    except OSError as exc:
        source["reason"] = f"unreadable: {exc.strerror or type(exc).__name__}"
    else:
        source.update(
            readable=True,
            truncated=len(data) > cap,
            modified=datetime.fromtimestamp(mtime, UTC).isoformat(timespec="seconds"),
            text=data[:cap].decode("utf-8", errors="replace"),
        )
    return source


def _public_source(source: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in source.items() if key != "text"}


def _snapshot_sections(text: str) -> dict[str, str]:
    """The dump's `## <command>` sections, each as its text."""
    sections: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in text.splitlines():
        if line.startswith("## "):
            current = sections.setdefault(line[3:].strip(), [])
        elif current is not None:
            current.append(line)
    return {name: "\n".join(lines) for name, lines in sections.items()}


def _failed_command(section: str, command: str) -> int | None:
    """The non-zero exit the dump recorded for a command, if it recorded one."""
    for name, code in _COMMAND_EXIT_RE.findall(section):
        if name == command and int(code) != 0:
            return int(code)
    return None


def read_kernel_snapshot(rootfs: str, now: datetime | None = None) -> dict[str, Any]:
    """What the host's root timer last saw of ufw in the kernel, and whether to trust it.

    `state` is one of: verified, inactive, stale, not_deployed, unreadable, malformed,
    ufw_error, nft_error, chains_missing, unconfirmed. Only `verified` and `inactive`
    answer the kernel question. A missing file is not_deployed, never inactive.
    """
    now = now or datetime.now(UTC)
    source = _read_file(rootfs, SNAPSHOT_PATH, MAX_SNAPSHOT_BYTES)
    reading: dict[str, Any] = {
        "state": "unreadable",
        "source": _public_source(source),
        "taken": None,
        "host": None,
        "age_seconds": None,
        "stale": None,
        "ufw_status": None,
        "ufw_chains": [],
        "problem": None,
    }
    if not source["readable"]:
        if source["reason"] == "absent":
            reading["state"] = "not_deployed"
            reading["problem"] = (
                f"{SNAPSHOT_PATH} is absent: the snapshot timer is not deployed or has not run."
            )
        else:
            reading["problem"] = f"{SNAPSHOT_PATH} could not be read ({source['reason']})."
        return reading

    text = source["text"]
    header = _SNAPSHOT_HEADER_RE.match(text.partition("\n")[0])
    try:
        taken = datetime.fromisoformat(header.group(1).replace("Z", "+00:00")) if header else None
    except ValueError:
        taken = None
    if header is None or taken is None:
        reading["state"] = "malformed"
        reading["problem"] = "line 1 is not `# host-firewall-snapshot <UTC ISO8601> host=<name>`."
        return reading
    if taken.tzinfo is None:
        taken = taken.replace(tzinfo=UTC)
    modified = datetime.fromisoformat(source["modified"])
    # The larger age decides: a touched file or an old header alone cannot pass.
    age = max(0, int(max((now - modified).total_seconds(), (now - taken).total_seconds())))
    reading.update(
        taken=taken.isoformat(timespec="seconds"),
        host=header.group(2),
        age_seconds=age,
        stale=age > STALE_AFTER_SECONDS,
    )

    sections = _snapshot_sections(text)
    ufw = sections.get("ufw status verbose")
    nft = sections.get("nft list ruleset")
    status = _UFW_STATUS_RE.search(ufw) if ufw is not None else None
    reading["ufw_status"] = status.group(1) if status else None
    chains = sorted(set(_UFW_CHAIN_RE.findall(nft))) if nft is not None else []
    reading["ufw_chains"] = chains

    if reading["stale"]:
        reading["state"] = "stale"
        reading["problem"] = (
            f"the snapshot is {age}s old, past {STALE_AFTER_SECONDS}s: the timer may have stopped."
        )
    elif ufw is None:
        reading["state"] = "malformed"
        reading["problem"] = "the `## ufw status verbose` section is missing."
    elif (code := _failed_command(ufw, "ufw")) is not None:
        reading["state"] = "ufw_error"
        reading["problem"] = f"ufw exited {code} on the host, so the kernel state is unknown."
    elif status is None:
        reading["state"] = "ufw_error"
        reading["problem"] = "the ufw section has no `Status:` line, so the kernel state is unknown"
    elif status.group(1) == "inactive":
        reading["state"] = "inactive"
    elif nft is None or (code := _failed_command(nft, "nft")) is not None:
        reading["state"] = "nft_error"
        reading["problem"] = (
            "ufw reports active but the nft ruleset is missing or failed"
            + (f" (nft exited {code})" if nft is not None else "")
            + ", so its chains are unconfirmed."
        )
    elif "ufw-user-input" in chains:
        reading["state"] = "verified"
    elif source["truncated"]:
        reading["state"] = "unconfirmed"
        reading["problem"] = (
            f"the dump is cut at {MAX_SNAPSHOT_BYTES} bytes before a ufw chain appears, "
            "so a missing chain is not proven."
        )
    else:
        reading["state"] = "chains_missing"
        reading["problem"] = "ufw reports active but ufw-user-input is not in the nft ruleset."
    return reading


def parse_settings(text: str) -> dict[str, str]:
    """KEY=value lines from ufw.conf or /etc/default/ufw, keys upper-cased.

    Mirrors ufw's own reader, which lower-cases values and strips quotes.
    """
    settings: dict[str, str] = {}
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = _KEY_VALUE_RE.match(line)
        if match:
            settings[match.group(1).upper()] = match.group(2).lower()
    return settings


def _policy_word(value: str | None) -> str | None:
    if value is None:
        return None
    return _POLICY_WORDS.get(value, "deny")


def _decode_comment(raw: str) -> str:
    raw = raw.strip()
    if _HEX_RE.match(raw):
        try:
            decoded = bytes.fromhex(raw).decode("utf-8")
        except UnicodeDecodeError:
            decoded = ""
        if decoded.isprintable():
            raw = decoded
    return raw[:MAX_COMMENT_CHARS]


def _parse_direction(token: str) -> dict[str, Any]:
    direction, _, _ = token.partition("_")
    interface_in = interface_out = None
    if "!" in token:
        in_part, _, out_part = token.partition("!")
        interface_in = in_part.partition("_")[2] or None
        interface_out = out_part.partition("_")[2] or None
    elif token.startswith("in_"):
        interface_in = token.partition("_")[2] or None
    elif token.startswith("out_"):
        interface_out = token.partition("_")[2] or None
    return {
        "direction": direction.split("!")[0],
        "interface_in": interface_in,
        "interface_out": interface_out,
    }


def _port_ranges(spec: str) -> list[tuple[int, int]] | None:
    """Port ranges for a ufw port spec, None for any. Raises ValueError if malformed."""
    if spec == "any":
        return None
    ranges = []
    for part in spec.split(","):
        low, _, high = part.partition(":")
        ranges.append((int(low), int(high or low)))
    return ranges


def _summary(rule: dict[str, Any]) -> str:
    target = rule["protocol"] if rule["dport"] == "any" else f"{rule['protocol']}/{rule['dport']}"
    parts = [rule["action"], rule["direction"]]
    if rule["interface_in"]:
        parts.append(f"on {rule['interface_in']}")
    if rule["interface_out"]:
        parts.append(f"out on {rule['interface_out']}")
    parts.append(target)
    if rule["dst"] not in _ANY_ADDRESSES:
        parts.append(f"to {rule['dst']}")
    parts.append(f"from {rule['src']}")
    if rule["sport"] != "any":
        parts.append(f"port {rule['sport']}")
    return " ".join(parts)


def parse_tuple(line: str) -> dict[str, Any]:
    """Parse one `### tuple ###` line, the record ufw itself rebuilds its rules from.

    Raises ValueError for a line that does not have ufw's shape, so the caller can
    count it rather than drop it.
    """
    comment = ""
    if " comment=" in line:
        line, _, raw_comment = line.partition(" comment=")
        comment = _decode_comment(raw_comment)
    fields = line.replace("### tuple ###", "", 1).split()
    if not 6 <= len(fields) <= 9:
        raise ValueError(f"expected 6 to 9 fields, got {len(fields)}")
    action_token, protocol, dport, dst, sport, src, *rest = fields
    where: dict[str, Any] = {"direction": "in", "interface_in": None, "interface_out": None}
    if rest and _DIRECTION_RE.match(rest[-1]):
        where = _parse_direction(rest.pop())
    route = action_token.startswith("route:")
    action, _, log = action_token.removeprefix("route:").partition("_")
    _port_ranges(dport)
    _port_ranges(sport)
    rule = {
        "action": action,
        "route": route,
        "log": log or None,
        "protocol": protocol,
        "dport": dport,
        "dst": dst,
        "sport": sport,
        "src": src,
        **where,
        "dst_app": rest[0] if rest and rest[0] != "-" else None,
        "src_app": rest[1] if len(rest) > 1 and rest[1] != "-" else None,
        "comment": comment or None,
    }
    rule["summary"] = _summary(rule)
    return rule


def parse_rules(text: str) -> tuple[list[dict[str, Any]], int]:
    """Every rule in a user.rules file, in file order, and the count that did not parse."""
    rules: list[dict[str, Any]] = []
    unparsed = 0
    for line in text.splitlines():
        if not line.startswith("### tuple ###"):
            continue
        try:
            rules.append(parse_tuple(line.rstrip()))
        except ValueError:
            unparsed += 1
    for position, rule in enumerate(rules, start=1):
        rule["position"] = position
    return rules, unparsed


def _is_any(value: str) -> bool:
    return value in _ANY_ADDRESSES


def _applies(rule: dict[str, Any], listener: dict[str, Any]) -> tuple[bool, bool]:
    """Whether an input rule covers this listener, and whether only for some sources."""
    if rule["route"] or rule["direction"] != "in":
        return False, False
    if rule["protocol"] not in ("any", listener["protocol"]):
        return False, False
    try:
        ranges = _port_ranges(rule["dport"])
    except ValueError:
        return False, False
    if ranges is not None and not any(low <= listener["port"] <= high for low, high in ranges):
        return False, False
    restricted = (
        not _is_any(rule["src"]) or rule["sport"] != "any" or rule["interface_in"] is not None
    )
    if not _is_any(rule["dst"]):
        if listener["address"] in _WILDCARD_BINDS:
            restricted = True
        else:
            try:
                inside = ipaddress.ip_address(listener["address"]) in ipaddress.ip_network(
                    rule["dst"], strict=False
                )
            except ValueError:
                inside = False
            if not inside:
                return False, False
    return True, restricted


def _is_loopback(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


def _verdict_word(action: str) -> str:
    return "allow" if action in ("allow", "limit") else action


def _exposure(
    listener: dict[str, Any],
    rules: list[dict[str, Any]],
    default_incoming: str | None,
    filtering: bool | None,
    reason: str,
) -> dict[str, Any]:
    entry = {**listener}
    if _is_loopback(listener["address"]):
        return {**entry, "verdict": "loopback_only", "decided_by": "bound to loopback"}
    if filtering is None:
        return {**entry, "verdict": "unknown", "decided_by": reason}
    if not filtering:
        return {**entry, "verdict": "not_filtered_by_ufw", "decided_by": reason}
    restricted_rules: list[str] = []
    verdict, decided_by = default_incoming or "unknown", "default incoming policy"
    for rule in rules:
        covers, restricted = _applies(rule, listener)
        if not covers:
            continue
        if restricted:
            restricted_rules.append(f"#{rule['position']} {rule['summary']}")
            continue
        verdict, decided_by = _verdict_word(rule["action"]), f"rule #{rule['position']}"
        break
    return {
        **entry,
        "verdict": verdict,
        "decided_by": decided_by,
        "restricted_rules": restricted_rules,
    }


def _header(
    enabled: bool | None, settings: dict[str, str], defaults: dict[str, str | None]
) -> list[str]:
    """The lines `ufw status verbose` prints above its rule table, for a by-eye match."""
    if not enabled:
        return ["Status: inactive"]
    level = settings.get("LOGLEVEL", "low")
    logging = "off" if level == "off" else f"on ({level})"
    profiles = settings.get("DEFAULT_APPLICATION_POLICY", "skip")
    return [
        "Status: active",
        f"Logging: {logging}",
        f"Default: {defaults['incoming']} (incoming), {defaults['outgoing']} (outgoing), "
        f"{defaults['routed']} (routed)",
        f"New profiles: {profiles}",
    ]


def _kernel_notes(kernel: dict[str, Any], enabled: bool | None, ipv6_managed: bool) -> list[str]:
    """Plain-language lines for the kernel reading, including where it disagrees with the config."""
    state, age = kernel["state"], kernel["age_seconds"]
    if state == "verified":
        notes = [f"kernel chains verified from the host snapshot of {kernel['taken']}, {age}s old."]
        if ipv6_managed and "ufw6-user-input" not in kernel["ufw_chains"]:
            notes.append("IPV6=yes but ufw6-user-input is not in the snapshot's nft ruleset.")
    elif state == "inactive":
        notes = [f"the host snapshot ({age}s old) shows ufw inactive in the kernel."]
    else:
        notes = [f"kernel state not read: {kernel['problem']}"]
    if state == "inactive" and enabled:
        notes.append("ufw.conf says ENABLED=yes but the kernel shows ufw inactive: not filtering.")
    if state == "verified" and enabled is False:
        notes.append("ufw.conf says ENABLED=no but the kernel shows ufw active: config is stale.")
    return notes


def snapshot(
    rootfs: str,
    listeners: list[dict[str, Any]],
    listener_notes: list[str],
    limit: int = DEFAULT_LIMIT,
    now: datetime | None = None,
) -> dict[str, Any]:
    """ufw state and, per listening socket, what the input rules decide for it."""
    limit = max(1, min(limit, MAX_LIMIT))
    kernel = read_kernel_snapshot(rootfs, now)
    conf = _read_file(rootfs, UFW_CONF)
    defaults_file = _read_file(rootfs, UFW_DEFAULTS)
    rule_files = {family: _read_file(rootfs, path) for family, path in UFW_RULES.items()}
    notes: list[str] = list(listener_notes)

    conf_settings = parse_settings(conf.get("text", ""))
    default_settings = parse_settings(defaults_file.get("text", ""))
    enabled: bool | None = conf_settings.get("ENABLED") == "yes" if conf["readable"] else None
    ipv6_managed: bool | None = (
        default_settings.get("IPV6") == "yes" if defaults_file["readable"] else None
    )
    policies = {
        "incoming": _policy_word(default_settings.get("DEFAULT_INPUT_POLICY")),
        "outgoing": _policy_word(default_settings.get("DEFAULT_OUTPUT_POLICY")),
        "routed": _policy_word(default_settings.get("DEFAULT_FORWARD_POLICY")),
    }

    if not conf["readable"]:
        status = "unknown"
        if conf["reason"] == "absent":
            notes.append(
                f"{UFW_CONF} is absent: ufw is not installed here, or ROOTFS is not the host root."
            )
        else:
            notes.append(
                f"{UFW_CONF} could not be read ({conf['reason']}), so the ufw state is UNKNOWN, "
                "not inactive."
            )
    else:
        status = "enabled_in_config" if enabled else "inactive"
    notes.extend(_kernel_notes(kernel, enabled, default_settings.get("IPV6") == "yes"))
    if enabled and kernel["state"] not in ("verified", "inactive"):
        notes.append(
            "enabled_in_config reads ENABLED in ufw.conf. `ufw status` also confirms the "
            "ufw-user-input chain is loaded in the kernel. The pod lacks CAP_NET_ADMIN to read "
            "it, and the host snapshot did not settle it (see `kernel`), so "
            "kernel_chains_verified is false."
        )
    elif conf["readable"] and not enabled:
        notes.append(
            "ufw is not filtering. Any other netfilter rules (nftables, iptables, kube-proxy) "
            "are not read by this tool."
        )

    rules: dict[str, list[dict[str, Any]]] = {}
    unparsed: dict[str, int] = {}
    truncated: dict[str, bool] = {}
    for family, source in rule_files.items():
        parsed, unparsed[family] = parse_rules(source.get("text", ""))
        truncated[family] = len(parsed) > limit
        rules[family] = parsed
        if not source["readable"]:
            notes.append(
                f"{source['path']} could not be read ({source['reason']}), so the {family} "
                "rule list is missing, not empty."
            )
        if unparsed[family]:
            notes.append(
                f"{unparsed[family]} tuple line(s) in {source['path']} did not parse and are "
                "left out of the rules and the listener verdicts."
            )

    exposures = []
    for listener in listeners:
        family = listener["family"]
        filtering = enabled
        reason = "ufw is inactive" if enabled is False else f"{UFW_CONF} unreadable"
        # A fresh kernel reading outranks the config, which can outlive its chains.
        if kernel["state"] == "inactive":
            filtering, reason = False, "the host snapshot shows ufw inactive in the kernel"
        elif kernel["state"] == "verified":
            filtering = True
        if filtering and family == "v6" and not ipv6_managed:
            filtering, reason = False, "IPV6=no in /etc/default/ufw, so ufw leaves ip6tables alone"
        exposures.append(
            _exposure(listener, rules[family], policies["incoming"], filtering, reason)
        )
    counts: dict[str, int] = {}
    for item in exposures:
        counts[item["verdict"]] = counts.get(item["verdict"], 0) + 1
    if len(exposures) > limit:
        notes.append(f"listeners truncated to {limit} of {len(exposures)}.")
    if exposures:
        notes.append(
            "Verdicts cover the INPUT path only. Traffic NAT-ed to a pod (NodePort, hostPort "
            "through kube-proxy) crosses FORWARD, whose default is the routed policy."
        )

    return {
        "status": status,
        "enabled_in_config": enabled,
        "kernel_chains_verified": kernel["state"] == "verified",
        "kernel": kernel,
        "ipv6_managed": ipv6_managed,
        "default_policy": policies,
        "logging": conf_settings.get("LOGLEVEL") if conf["readable"] else None,
        "status_verbose_header": _header(enabled, {**default_settings, **conf_settings}, policies),
        "rules": {family: items[:limit] for family, items in rules.items()},
        "rule_counts": {family: len(items) for family, items in rules.items()},
        "rules_truncated": truncated,
        "unparsed_tuples": unparsed,
        "listeners": exposures[:limit],
        "listener_verdict_counts": dict(sorted(counts.items())),
        "sources": {
            "conf": _public_source(conf),
            "defaults": _public_source(defaults_file),
            **{f"rules_{family}": _public_source(source) for family, source in rule_files.items()},
        },
        "notes": notes,
    }
