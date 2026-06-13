# dae

<img src="https://github.com/daeuniverse/dae/blob/main/logo.png" border="0" width="25%">

<p align="left">
    <img src="https://github.com/daeuniverse/dae/actions/workflows/build.yml/badge.svg" alt="Build"/>
    <img src="https://custom-icon-badges.herokuapp.com/github/license/daeuniverse/dae?logo=law&color=orange" alt="License"/>
    <img src="https://custom-icon-badges.herokuapp.com/github/v/release/daeuniverse/dae?logo=rocket" alt="version">
    <img src="https://custom-icon-badges.herokuapp.com/github/issues-pr-closed/daeuniverse/dae?color=purple&logo=git-pull-request&logoColor=white"/>
    <img src="https://custom-icon-badges.herokuapp.com/github/last-commit/daeuniverse/dae?logo=history&logoColor=white" alt="lastcommit"/>
</p>

> **This is an enhanced fork** with disaster-recovery capabilities for the `fixed` dialer mode.
> See [Releases](https://github.com/itoywh/dae/releases) for pre-built binaries.

## Fork Enhancements

### 1. fixed_fallback — Disaster-Recovery Dialer Strategy

The original `fixed` dialer mode has a critical weakness: **if the fixed node goes down, traffic stops entirely**. There is no failover mechanism — it's a single point of failure.

This fork introduces `fixed_fallback`, transforming `fixed` from a fragile standalone mode into a **production-grade high-availability strategy** with full disaster-recovery semantics.

---

#### Quick Start

```ini
# In your dae config (e.g., /etc/dae/config.dae):
[group]
my_group {
    dial_mode: fixed_fallback(1, 5s, 3)
}

[global]
check_tolerance: 60ms
```

This means: prefer the 2nd node in the group (index 1, 0-based). If it fails after 3 connection attempts with 5 seconds timeout each → automatically switch to the best available node. When the fixed node recovers → automatically switch back. The 60ms tolerance prevents flapping.

---

#### Parameter Reference

```
fixed_fallback(<index>, <timeout>, <retries>[, <fallback_policy>])
```

| # | Parameter | Required | Description | Example |
|---|-----------|----------|-------------|---------|
| 1 | **`index`** | ✅ | 0-based index of the fixed dialer in the group's node list. The first node is `0`, second is `1`, etc. Must point to a valid node — if out of range, falls through to fallback pool. | `1` → use the 2nd node |
| 2 | **`timeout`** | ✅ | Connection timeout per attempt. Supports unit suffixes: `ms` (milliseconds), `s` (seconds), `m` (minutes). Without suffix, treated as seconds (backward compatible). | `5s`, `500ms`, `2m`, `10` (10s) |
| 3 | **`retries`** | ✅ | Maximum connection retries before declaring the fixed node dead and triggering fallback. After all retries are exhausted, a WARN-level log is emitted. | `3` → retry 3 times |
| 4 | **`fallback_policy`** | ❌ | Fallback node selection strategy when the fixed node is down. If omitted, defaults to `min_moving_avg`. | See table below |

##### Fallback Strategy Options

| Policy | Behavior | Best For |
|--------|----------|----------|
| `min_moving_avg` ⭐ *(default)* | Selects the node with the lowest moving-average latency. Works with `check_tolerance` to prevent unnecessary switches. | General use — latency-sensitive traffic |
| `min_last_latency` | Selects the node with the lowest most-recent measured latency. | Environments with rapidly changing network conditions |
| `random` | Randomly picks an alive node from the fallback pool. | Load balancing — when you want to distribute traffic across the fallback pool |

##### How `check_tolerance` Works with fixed_fallback

The `check_tolerance` setting (under `[global]`) works alongside the fallback policy to prevent node flapping. When the fixed node recovers and its latency is within `check_tolerance` of the current fallback node's latency, dae will **not** switch back immediately — avoiding the "bounce" effect where traffic oscillates between nodes.

```ini
[global]
check_tolerance: 60ms   # Only switch back if fixed node is ≥60ms better than fallback
```

---

#### How It Works

```
┌─ Normal operation ─────────────────────────────────────────┐
│                                                             │
│  fixed_fallback(1, 5s, 3, min_moving_avg)                  │
│                                                             │
│  1. Try fixed node (index 1 = 2nd node)                    │
│     ├─ Alive? → Use it. Done. ✅                            │
│     └─ Down/Timeout? → Retry (up to 3 times)               │
│                                                             │
│  2. All 3 retries exhausted?                                │
│     └─ WARN log: "fixed dialer retries exhausted (3/3)"    │
│        → Fall back to min_moving_avg among alive nodes     │
│        → INFO log: "falling back to <node>"                │
│                                                             │
│  3. Connectivity Checker probes fixed node periodically     │
│     └─ Fixed node recovered?                                │
│        ├─ Latency within check_tolerance? → Stay on fallback│
│        └─ Latency significantly better? → Switch back 🔄   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

#### Configuration Examples

**Example A: Simple failover** — prefer node `s4`, fall back to any alive node when unavailable:
```ini
[group]
my_group {
    nodes: s4, s2, s5
    dial_mode: fixed_fallback(0, 5s, 3)
}
```

**Example B: with random fallback** — distribute fallback traffic across all backup nodes:
```ini
[group]
my_group {
    nodes: s4, s2, s5
    dial_mode: fixed_fallback(0, 3s, 2, random)
}
```

**Example C: with check_tolerance** — prevent flapping when latencies are close:
```ini
[global]
check_tolerance: 80ms

[group]
my_group {
    nodes: s_hk, s_jp, s_sg
    dial_mode: fixed_fallback(0, 5s, 3)        # min_moving_avg (default)
}
```

**Example D: Aggressive timeout** — fail fast, retry only once:
```ini
dial_mode: fixed_fallback(0, 500ms, 1, min_last_latency)
```

---

#### Compatibility

- **Backward compatible**: existing `fixed_fallback(1, 5s, 3)` configs work without changes
- **Time unit backward compatibility**: `fixed_fallback(1, 5, 3)` (no suffix) still works — treated as seconds
- **Works with all existing dialer strategies**: `fixed_fallback` is an additional strategy, all other strategies (`random`, `min_moving_avg`, etc.) continue to work as-is

---

### 2. Improved Log Format

Log timestamps now use human-readable format with `ForceFormatting` enabled:

```
Before:  INFO selected dialer: s4 ...
After:  [2026-06-13 15:04:05] INFO selected dialer: s4 ...
```

The format `[YYYY-MM-DD HH:MM:SS]` prefix makes logs easier to read and parse with standard tools (e.g., `grep`, `awk`, log viewers).

---

### Upstream PRs

- [PR #1009](https://github.com/daeuniverse/dae/pull/1009) — fixed_fallback disaster-recovery enhancement
- [PR #1010](https://github.com/daeuniverse/dae/pull/1010) — log timestamp format improvement

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
