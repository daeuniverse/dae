# Troubleshooting

## No network after `dae suspend`

Do not advertise dae as the DNS server in your DHCP settings: suspended dae
does not intercept DNS requests. Advertise a server such as `223.5.5.5` instead.

## PVE

- [PVE NIC Hardware passthrough](https://github.com/daeuniverse/dae/issues/43)

## dae fails to start with a leftover `/run/netns/daens`

A previous run left the named netns mount point `/run/netns/daens` behind. On
hosts where dae runs inside a user namespace context (LXC guests such as a
Proxmox VE container, sandboxed services), the kernel can lock that mount point
(`MNT_LOCKED`): `umount`, `umount -l` and `umount -f` all fail with `EINVAL`
while `rm` reports `EBUSY`, so no retry or flag combination clears it. The
namespace itself is gone; only the mount point survives.

Current builds detect exactly this signature and recover automatically: dae
covers `/run/netns` with a fresh tmpfs, logs a warning that names the recovery
and every other named netns the cover hides, and starts on the clean directory.
The cover persists until the next reboot — that is intentional; removing it
would expose the stale entry again. Older builds reported the misleading
`failed to create netns: open /run/netns/daens: file exists`.

dae recovers only for that exact signature. Any other refusal — a different
errno, or an environment where dae itself may not mount (for example a missing
capability in the surrounding container) — fails fast with
`failed to clean up the stale named netns daens: ...`, which carries the real
errnos. When the refusal is a privilege problem, the fallback below needs the
same privilege:

```bash
sudo mount -t tmpfs -o mode=755 tmpfs /run/netns
sudo systemctl start dae
```

Run that mount inside the same mount namespace as dae; in a container, run it
from inside the container rather than from the host.

The tmpfs hides every named netns in that mount namespace: `ip netns list`
reads the same directory, so names other than `daens` disappear from it, and
`ip netns exec`, `ip netns pids` and `ip netns delete` stop finding them. The
hidden namespaces and their processes keep running; only their names become
unreachable. The cover is a mount in dae's mount namespace, so it also
outlives dae itself until then, including a start that later fails for an
unrelated reason. Nothing in `/run` survives a reboot: the reboot clears the
cover and the stale entry, and the other named netns return when the tools
that own them recreate them. See
[issue #1109](https://github.com/daeuniverse/dae/issues/1109).

## Binding to WAN but no network

### Troubleshoot local DNS service

If you use AdGuardHome or mosdns in the `dns` section, see [Use external DNS](configuration/external-dns.md).

### Troubleshoot firewall

dae redirects hijacked packets from the WAN egress and LAN ingress tc hooks over the `dae0` device into its private `daens` network namespace.
Inside `daens`, `tproxy_dae0peer_ingress` sets mark `0x8000000`, and a namespace-local policy route (table `2023`) delivers the packet to the tproxy listener on `tproxy_port` (default `12345`).
The host `INPUT` chain never sees these packets or that mark, so a host firewall rule for the mark or for the port does not affect them.
dae installs no firewall rule for the port and ignores the deprecated `auto_config_firewall_rule` option.
The host firewall does see dae's own outbound connections and the replies dae injects back on the WAN interface.
A ruleset that accepts established and related traffic passes both.
If you bind to WAN and lose network, stop the firewall to confirm that the firewall is the cause.
Then check that its ruleset accepts established and related traffic, as the default ufw and firewalld rulesets do.

Common Linux firewalls:

```bash
ufw
firewalld
```

#### ufw

The default `/etc/ufw/before*.rules` accept established and related traffic, which covers the replies dae injects on the WAN interface.
Older guides add the following mark rules to `/etc/ufw/before*.rules`.
These rules match no packet on the host, because hijacked packets carry mark `0x8000000` only inside `daens`.
dae does not need them:

```bash
# before.rules
-A ufw-before-input -m mark --mark 0x8000000 -j ACCEPT

# before6.rules
-A ufw6-before-input -m mark --mark 0x8000000 -j ACCEPT
```

#### firewalld

The default firewalld zones accept established and related traffic, which covers the replies dae injects on the WAN interface.
Older guides run the following command after every boot and firewall rule change.
The command matches no packet on the host, because hijacked packets carry mark `0x8000000` only inside `daens`.
dae does not need it:

```bash
sudo nft 'insert rule inet firewalld filter_INPUT mark 0x8000000 accept'
```

### Troubleshoot PPPoE

Older dae versions do not support PPPoE. Use the latest version.

## Binding to LAN but DNS fails on other machines

### Check dae's configuration

Make sure dae is bound to the correct LAN interfaces.

- If `eth1` serves both WAN and LAN, set both `wan_interface: eth1` and `lan_interface: eth1`.
- If you want to proxy `eth1` and `docker0` as LAN interfaces, set `lan_interface: eth1,docker0`.

### Troubleshoot DNS

Run these commands on another LAN machine:

```bash
curl -i 1.1.1.1
curl -i google.com
```

If only the first command gets a response, check whether another service occupies port `53` on the dae host:

```bash
netstat -ulpen|grep 53
# or
# lsof -i:53 -n
```

If another service uses port 53, stop it or change its listening port.
Update `/etc/resolv.conf` so DNS remains accessible. For example, use
`nameserver 223.5.5.5`, not `nameserver 127.0.0.1`.

## Failed to load eBPF objects

> FATA[0022] load eBPF objects: field TproxyWanEgress: program tproxy_wan_egress: load program: argument list too long: 1617: (bf) r2 = r6: 1618: (85) call bpf_map_loo (truncated, 992 line(s) omitted)

This error occurs when `clang-13` compiles dae.
Compile with `clang-15` or later, or download a binary from [releases](https://github.com/daeuniverse/dae/releases).
`-D__UNROLL_ROUTE_LOOP` has no effect: the macro is a commented-out define in `control/kern/tproxy.c` with no code behind it.
Routing always uses `bpf_loop`, and dae refuses to start on kernels older than `5.17.0`.
