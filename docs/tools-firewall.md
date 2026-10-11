# Host firewall tool

`get_host_firewall` answers what a seat otherwise asks Kai to run `sudo ufw status verbose` for. It is read-only, like every tool here, and part of [host tools](tools-host.md).

It returns whether ufw is enabled, the default policies, the IPv4 and IPv6 rules in file order, and for each listening socket what the input rules decide. `limit` (default 100, max 500) caps rules per family and listeners. `rule_counts` stays true when the list is cut.

## Where the answer comes from

Four fixed files under `ROOTFS`, which are the files `ufw` itself rebuilds its state from. The tool takes no path, runs no command, and has no write path.

- `/etc/ufw/ufw.conf` - `ENABLED` and `LOGLEVEL`. Mode 0644.
- `/etc/default/ufw` - `IPV6` and the default input, output, and forward policies. Mode 0644.
- `/etc/ufw/user.rules` and `/etc/ufw/user6.rules` - one `### tuple ###` line per rule. Mode 0640 root:root.

`sources` reports each file's readability, size cap, and modification time, so a stale rules file shows its age.

## What it cannot confirm

**`kernel_chains_verified` is always false.** `ufw status` builds its rule table from the same files but also runs `iptables -L ufw-user-input` and prints `inactive` when that chain is missing from the kernel. Reading the chain needs `CAP_NET_ADMIN`, which the pod does not hold.

- `status: inactive` - `ENABLED=no`. `ufw disable` flushes the chains, so this is the strong answer.
- `status: enabled_in_config` - `ENABLED=yes`. Whether the chains actually loaded is open, and the notes say so.
- `status: unknown` - `ufw.conf` is absent or unreadable. An absent file means ufw is not installed here, and is never read as inactive.

When ufw is not filtering, a listener's verdict is `not_filtered_by_ufw`. Other netfilter rules (nftables, iptables, kube-proxy) are not read, so it never says `allow` for a socket ufw is not guarding. The same verdict covers IPv6 listeners when `IPV6=no`, because ufw then leaves ip6tables alone.

## Reading a listener verdict

Each listening TCP socket and unconnected UDP socket gets a `verdict` of `allow`, `deny`, `reject`, `loopback_only`, `not_filtered_by_ufw`, or `unknown`, and `decided_by` names the rule number or the default input policy.

The verdict is for a source that matches no restricted rule. A rule is **restricted** when it names a source, a source port, an input interface, or a destination narrower than a wildcard listener. Restricted rules are listed in `restricted_rules` and never decide the verdict, so `deny` with `#2 allow in on tailscale0 ...` means "denied, except from that source".

The verdict covers the INPUT path. Traffic NAT-ed to a pod, such as a NodePort through kube-proxy, crosses FORWARD, whose default is `default_policy.routed`. A `::` listener can also accept IPv4 unless the socket is v6-only, so check both families for a port.

`status_verbose_header` holds the lines `ufw status verbose` prints above its table (`Status`, `Logging`, `Default`, `New profiles`) for a by-eye match with a reference run. Rule `summary` strings follow ufw's wording but are not its table.

## The privilege it needs

**No new grant on the current deploy.** The `node-stats-mcp` container already runs as uid 0 with the node's `/` mounted read-only at `/host` in both deploy manifests, which is how it already reads `/host/etc/rancher/k3s/k3s.yaml`. The four files above are readable through that mount.

A deploy that drops to a non-root user needs read access to those four files and nothing else. A live read of the kernel chains is the one thing this design leaves out, and it would need `CAP_NET_ADMIN` or a root-owned helper that dumps `ufw status verbose` to a file the pod reads. It is not granted.

## Parsing notes

- The tuple line is `action protocol dport dst sport src [dapp sapp] direction`, with an optional trailing ` comment=` that ufw hex-encodes. Parsed from ufw 0.36 (`backend_iptables._read_rules`), which both hosts run.
- `action` can carry a `route:` prefix and a `_log` or `_log-all` suffix. `direction` can carry an interface (`in_tailscale0`, `in_eth0!out_cni0`).
- A line that does not parse is counted in `unparsed_tuples` and noted, never dropped silently.
