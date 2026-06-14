# dae

<img src="https://github.com/daeuniverse/dae/blob/main/logo.png" border="0" width="25%">

<p align="left">
    <img src="https://github.com/daeuniverse/dae/actions/workflows/build.yml/badge.svg" alt="Build"/>
    <img src="https://custom-icon-badges.herokuapp.com/github/license/daeuniverse/dae?logo=law&color=orange" alt="License"/>
    <img src="https://custom-icon-badges.herokuapp.com/github/v/release/daeuniverse/dae?logo=rocket" alt="version">
    <img src="https://custom-icon-badges.herokuapp.com/github/issues-pr-closed/daeuniverse/dae?color=purple&logo=git-pull-request&logoColor=white"/>
    <img src="https://custom-icon-badges.herokuapp.com/github/last-commit/daeuniverse/dae?logo=history&logoColor=white" alt="lastcommit"/>
</p>

<p align="left">
  <a href="README.md">English</a> | <a href="README_zh.md">简体中文</a>
</p>

> **This is an enhanced Fork** that adds full disaster recovery to the `fixed` dialing mode.
> Pre-built binaries are available at [Releases](https://github.com/itoywh/dae/releases).

## Fork Enhancements

### 1. fixed_fallback — Disaster-Recoverable Dialing Strategy

The stock `fixed` mode has a critical flaw: **if the fixed node fails, traffic is cut off immediately** — no failover mechanism, a single point of failure.

This Fork introduces `fixed_fallback`, upgrading `fixed` from a fragile single-node mode to a **production-grade high-availability strategy** with full disaster recovery semantics.

---

#### Quick Start

```ini
# In dae config file (e.g. /etc/dae/config.dae):
[group]
my_group {
    policy: fixed_fallback(1, 5s, 3)
}

[global]
check_tolerance: 60ms
```

Meaning: prefer the 2nd node in the group (index 1, 0-based). On failure, timeout 5s per attempt, retry up to 3 times → on total failure, auto-switch to the best alive node. When the fixed node recovers, switch back immediately. 60ms tolerance prevents flapping between s2/s5 during failover.

---

#### Parameter Reference

```
fixed_fallback(<index>, <timeout>, <retries>[, <fallback_policy>])
```

| # | Parameter | Required | Description | Example |
|---|-----------|----------|-------------|---------|
| 1 | **`index`** | ✅ | 0-based index of the fixed node in the group's node list. | `1` → use 2nd node |
| 2 | **`timeout`** | ✅ | Timeout per connection attempt. Supports unit suffixes: `ms`, `s`, `m`. No suffix = seconds (backward compatible). | `5s`, `500ms`, `2m`, `10` |
| 3 | **`retries`** | ✅ | Max retries before declaring the fixed node dead and triggering fallback. WARN-level log on exhaustion. | `3` |
| 4 | **`fallback_policy`** | ❌ | Policy for selecting fallback node after fixed node failure. Defaults to `min_moving_avg`. | See below |

##### Fallback Policy Options

| Policy | Behavior | Use Case |
|--------|-----------|----------|
| `min_moving_avg` ⭐ *(default)* | Select node with lowest moving average latency. Works with `check_tolerance` to prevent flapping. | General — latency-sensitive traffic |
| `min` | Select node with lowest last measured latency (official name, same as `min_last_latency`). | Environments with rapidly changing network conditions |
| `min_avg10` | Select node with lowest average latency over last 10 checks. | Environments with high latency variance |
| `random` | Randomly select from alive fallback nodes. | Load balancing — spread traffic across fallback pool |

##### `check_tolerance` with `fixed_fallback`

The `check_tolerance` config (under `[global]`) works with the fallback policy, **only affecting fallback node selection during disaster recovery**, preventing s2/s5 from flapping due to minor latency fluctuations.

```ini
[global]
check_tolerance: 60ms   # During failover: s2↔s5 switch only if latency diff ≥60ms
```

> **Important**: s4 recovery is completely independent of `check_tolerance`. Once s4 passes the liveness check, traffic switches back **immediately unconditionally** — no latency comparison, no tolerance threshold. `check_tolerance` governs "which backup is better", not "has the primary recovered".

---

#### How It Works

```
┌─ Normal Flow ────────────────────────────────────────────┐
│                                                             │
│  fixed_fallback(1, 5s, 3, min_moving_avg)             │
│                                                             │
│  1. Try fixed node (index 1 = 2nd node)                 │
│     ├─ Alive? → Use it. Done ✅                         │
│     └─ Dead/timeout? → Retry (max 3 times)             │
│                                                             │
│  2. All 3 retries exhausted?                               │
│     └─ WARN log: "fixed dialer retries exhausted (3/3)"  │
│        → Select best node by min_moving_avg                 │
│        → INFO log: "falling back to <node>"               │
│                                                             │
│  3. Connectivity Checker periodically probes fixed node     │
│     └─ Fixed node recovered? → Switch back immediately 🔄 │
│        (no check_tolerance comparison, alive = switch)      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

#### Configuration Examples

**Example A: Simple failover** — prefer s4, fall back to other alive nodes on failure:
```ini
[group]
my_group {
    nodes: s4, s2, s5
    policy: fixed_fallback(0, 5s, 3)
}
```

**Example B: Random fallback (load balancing)** — spread fallback traffic across backup nodes:
```ini
[group]
my_group {
    nodes: s4, s2, s5
    policy: fixed_fallback(0, 3s, 2, random)
}
```

**Example C: With `check_tolerance`** — prevent oscillation when latencies are close:
```ini
[global]
check_tolerance: 80ms

[group]
my_group {
    nodes: s_hk, s_jp, s_sg
    policy: fixed_fallback(0, 5s, 3)        # min_moving_avg (default)
}
```

**Example D: Aggressive timeout** — fast failure, single retry:
```ini
policy: fixed_fallback(0, 500ms, 1, min)
```

---

#### Compatibility

- **Backward compatible**: existing `fixed_fallback(1, 5s, 3)` config works without changes
- **Timeout unit backward compatible**: `fixed_fallback(1, 5, 3)` (no unit) still works — treated as seconds
- **Coexists with all existing policies**: `fixed_fallback` is a new policy; others (`random`, `min_moving_avg`, etc.) unchanged

---

### 2. Log Timestamp Format Optimization

Log timestamps now use human-readable format with `ForceFormatting` enabled:

```
Before: INFO selected dialer: s4 ...
After:  [2026-06-13 15:04:05] INFO selected dialer: s4 ...
```

The `[YYYY-MM-DD HH:MM:SS]` prefix aids readability and is compatible with standard log parsing tools (`grep`, `awk`, log viewers).

---

### 3. Fully Configuration-Driven Health Checks

> Corresponding upstream PR: [daeuniverse/dae#1011](https://github.com/daeuniverse/dae/pull/1011)

Stock dae hardcodes default values for `tcp_check_url`, `udp_check_dns`, and `check_interval`, so health checks always run even when the user didn't explicitly configure them. This Fork makes all health check options **fully optional** — if you don't write it, it won't check.

#### Core Rule

> **Health checks are now completely opt-in. Nothing runs unless you explicitly configure it.**

| Config | Behavior |
|---|---|
| `check_interval` not set or `0s` | **All health checks disabled**. Zero network probes. |
| `tcp_check_url` not set | No TCP connectivity checks at all. |
| `tcp_check_url` set (IPv4 only) | TCP IPv4 check only. IPv6 TCP probe auto-skipped. |
| `tcp_check_url` set (with IPv6) | TCP IPv4 + IPv6 checks both run. |
| `udp_check_dns` not set | No UDP DNS connectivity checks at all. |
| `udp_check_dns` set (IPv4 only) | UDP IPv4 DNS check only. IPv6 UDP probe auto-skipped. |
| `udp_check_dns` set (with IPv6) | UDP IPv4 + IPv6 DNS checks both run. |

#### Zero-Check Config (Maximum Performance)

```ini
global {
    # No tcp_check_url, no udp_check_dns, no check_interval
    # → Zero connectivity checks. Zero network probes. Maximum performance.
    log_level: info
}
```

#### TCP Check Only

```ini
global {
    tcp_check_url: 'http://cp.cloudflare.com,1.1.1.1'
    check_interval: 60s
    # udp_check_dns not set → no UDP checks
}
# Actual probes: tcp4 only (1 probe)
```

#### TCP + UDP, IPv4 Only (No IPv6)

```ini
global {
    tcp_check_url: 'http://cp.cloudflare.com,1.1.1.1'
    udp_check_dns: 'dns.google:53,8.8.8.8'
    check_interval: 60s
    check_tolerance: 50ms
}
# Actual probes: tcp4 + udp4_dns (2 probes, no IPv6)
```

#### Full Checks (IPv4 + IPv6)

```ini
global {
    tcp_check_url: 'http://cp.cloudflare.com,1.1.1.1,2606:4700:4700::1111'
    udp_check_dns: 'dns.google:53,8.8.8.8,2001:4860:4860::8888'
    check_interval: 60s
}
# Actual probes: tcp4 + tcp6 + udp4_dns + udp6_dns (4 probes)
```

#### Debug: View Current Probe Configuration

With `log_level: debug`, dae outputs the probe configuration for each dialer on startup:

```
DEBUG Connectivity check probes configured  dialer=my-node  tcp4=true tcp6=false udp4_dns=false udp6_dns=false
DEBUG Connectivity check disabled (check_interval=0)  dialer=my-node
```

> **Migration note**: If you upgrade from stock dae and want health checks, you must now explicitly add `tcp_check_url`, `udp_check_dns`, and `check_interval` to your config. They no longer have defaults.

---

### 4. Node Status Operational Logging

To enable fine-grained operational analysis without enabling debug mode, this Fork adds WARN/INFO-level logs for node state transitions:

#### Node-Level Events

| Event | Level | Trigger |
|---|---|---|
| `Node became DEAD` | **WARN** | Node transitions from ALIVE → DEAD (shows `network` type) |
| `Node became ALIVE` | **INFO** | Node recovers from DEAD → ALIVE (shows `latency` + `network`) |

#### Fixed-Fallback Events (existing)

| Event | Level | Trigger |
|---|---|---|
| `fixed dialer dead, starting retry` | **WARN** | Fixed node detected DEAD, entering retry phase |
| `fixed dialer retry N/M` | **INFO** | Per-retry attempt count |
| `fixed dialer retries exhausted, falling back` | **WARN** | All retries exhausted, switching to fallback pool |
| `fixed dialer recovered, traffic returned` | **INFO** | Fixed node revived, traffic unconditionally switched back |

#### Log Level Guide

| `log_level` | What You See |
|---|---|
| `info` | All WARN/INFO operational events above — ideal for production monitoring |
| `debug` | Everything above + per-check latency data + probe configuration — for deep analysis |

#### Example Log Output

```
[2026-06-14 02:02:36]  WARN Node became DEAD dialer=s4 network=tcp4
[2026-06-14 02:02:45]  WARN fixed dialer dead, starting retry (timeout=3s, max_retries=3)
[2026-06-14 02:03:19]  INFO fixed dialer retry 1/3
[2026-06-14 02:03:36]  WARN fixed dialer retries exhausted (3/3), falling back to min_moving_avg
[2026-06-14 02:15:00]  INFO Node became ALIVE dialer=s4 network=tcp4 latency=156ms
[2026-06-14 02:15:00]  INFO fixed dialer recovered, traffic returned
```

---

### Upstream PRs

- [PR #1009](https://github.com/daeuniverse/dae/pull/1009) — fixed_fallback disaster recovery enhancement
- [PR #1010](https://github.com/daeuniverse/dae/pull/1010) — Log timestamp format optimization
- [PR #1011](https://github.com/daeuniverse/dae/pull/1011) — Fully configurable health checks (opt-in)

---

**_dae_**, means goose, is a high-performance transparent proxy solution.

To enhance traffic split performance as much as possible, dae employs the transparent proxy and traffic split suite within the Linux kernel using eBPF. As a result, dae can enable direct traffic to bypass the proxy application's forwarding, facilitating genuine direct traffic passage. Through this remarkable feat, there is minimal performance loss and negligible additional resource consumption for direct traffic. 

As a successor of [v2rayA](https://github.com/v2rayA/v2rayA), dae abandoned v2ray-core to meet the needs of users more freely.

## Features

- [x] Implement `Real Direct` traffic split (need ipforward on) to achieve [high performance](https://docs.google.com/spreadsheets/d/1UaWU6nNho7edBNjNqC8dfGXLlW0-cm84MM7sH6Gp7UE/edit?usp=sharing).
- [x] Support to split traffic by process name in local host.
- [x] Support to split traffic by MAC address in LAN.
- [x] Support to split traffic with invert match rules.
- [x] Support to automatically switch nodes according to policy. That is to say, support to automatically test independent TCP/UDP/IPv4/IPv6 latencies, and then use the best nodes for corresponding traffic according to user-defined policy.
- [x] Support advanced DNS resolution process.
- [x] Support full-cone NAT for shadowsocks, trojan(-go) and socks5 (no test).
- [x] Support various trending proxy protocols, seen in [proxy-protocols.md](./docs/en/proxy-protocols.md).

## Getting Started

Please refer to [Quick Start Guide](./docs/en/README.md) to start using `dae` right away!

## Notes

1. If you setup dae and also a shadowsocks server (or any UDP servers) on the same machine in public network, such as a VPS, don't forget to add `l4proto(udp) && sport(your server ports) -> must_direct` rule for your UDP server port. Because states of UDP are hard to maintain, all outgoing UDP packets will potentially be proxied (depends on your routing), including traffic to your client. This behaviour is not what we want to see. `must_direct` makes all traffic from this port including DNS traffic direct.
1. If users in mainland China find that the first screen time is very long when they visit some domestic websites for the first time, please check whether you use foreign DNS to handle some domestic domain in DNS routing. Sometimes this is hard to spot. For example, `ocsp.digicert.cn` is included in `geosite:geolocation-!cn` unexpectedly, which will cause some tls handshakes to take a long time. Be careful to use such domain sets in DNS routing.

## How it works

See [How it works](./docs/en/how-it-works.md).

## TODO

- [ ] Automatically check dns upstream and source loop (whether upstream is also a client of us) and remind the user to add sip rule.
- [ ] MACv2 extension extraction.
- [ ] Log to userspace.
- [ ] Protocol-oriented node features detecting (or filter), such as full-cone (especially VMess and VLESS).
- [ ] Add quick-start guide
- [ ] ...

## Contributors

Special thanks goes to all [contributors](https://github.com/daeuniverse/dae/graphs/contributors). If you would like to contribute, please see the [instructions](./docs/en/development/contribute.md). Also, it is recommended following the [commit-msg-guide](./docs/en/development/commit-msg-guide.md).

## License

[AGPL-3.0 (C) daeuniverse](https://github.com/daeuniverse/dae/blob/main/LICENSE)

## Stargazers over time

[![Stargazers over time](https://starchart.cc/daeuniverse/dae.svg)](https://starchart.cc/daeuniverse/dae)
