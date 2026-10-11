"""Read-only ufw state, taken from ufw's own config files and never from netfilter.

The module reads four fixed files under ROOTFS and opens nothing a caller names.
It cannot change a rule: there is no write path and no subprocess. Live netfilter
needs CAP_NET_ADMIN, which the pod does not hold, so `kernel_chains_verified` is
always False and the result says what that leaves open. See docs/tools-firewall.md.
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


def _read_file(rootfs: str, path: str) -> dict[str, Any]:
    """Read one fixed file, bounded, reporting why it is absent rather than empty."""
    target = Path(rootfs).joinpath(path.lstrip("/"))
    source: dict[str, Any] = {"path": path, "readable": False}
    try:
        with target.open("rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
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
            truncated=len(data) > MAX_FILE_BYTES,
            modified=datetime.fromtimestamp(mtime, UTC).isoformat(timespec="seconds"),
            text=data[:MAX_FILE_BYTES].decode("utf-8", errors="replace"),
        )
    return source


def _public_source(source: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in source.items() if key != "text"}


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


def snapshot(
    rootfs: str,
    listeners: list[dict[str, Any]],
    listener_notes: list[str],
    limit: int = DEFAULT_LIMIT,
) -> dict[str, Any]:
    """ufw state and, per listening socket, what the input rules decide for it."""
    limit = max(1, min(limit, MAX_LIMIT))
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
    if enabled:
        notes.append(
            "enabled_in_config reads ENABLED in ufw.conf. `ufw status` also confirms the "
            "ufw-user-input chain is loaded in the kernel, which needs CAP_NET_ADMIN and is "
            "not read here (kernel_chains_verified is false)."
        )
    elif conf["readable"]:
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
        "kernel_chains_verified": False,
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
