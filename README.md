# dae

<img src="https://github.com/daeuniverse/dae/blob/main/logo.png" border="0" width="25%">

<p align="left">
    <img src="https://github.com/daeuniverse/dae/actions/workflows/build.yml/badge.svg" alt="Build"/>
    <img src="https://custom-icon-badges.herokuapp.com/github/license/daeuniverse/dae?logo=law&color=orange" alt="License"/>
    <img src="https://custom-icon-badges.herokuapp.com/github/v/release/daeuniverse/dae?logo=rocket" alt="version">
    <img src="https://custom-icon-badges.herokuapp.com/github/issues-pr-closed/daeuniverse/dae?color=purple&logo=git-pull-request&logoColor=white"/>
    <img src="https://custom-icon-badges.herokuapp.com/github/last-commit/daeuniverse/dae?logo=history&logoColor=white" alt="lastcommit"/>
</p>

**_dae_**, means goose, is a high-performance transparent proxy solution.

To enhance traffic split performance as much as possible, dae employs the transparent proxy and traffic split suite within the Linux kernel using eBPF. As a result, dae can enable direct traffic to bypass the proxy application's forwarding, facilitating genuine direct traffic passage. Through this remarkable feat, there is minimal performance loss and negligible additional resource consumption for direct traffic. 

As a successor of [v2rayA](https://github.com/v2rayA/v2rayA), dae abandoned v2ray-core to meet the needs of users more freely.

## Features

- [x] Implement `Real Direct` traffic split (need ipforward on) to achieve [high performance](https://docs.google.com/spreadsheets/d/1UaWU6nNho7edBNjNqC8dfGXLlW0-cm84MM7sH6Gp7UE/edit?usp=sharing).
- [x] Support to split traffic by process name in local host.
- [x] Support to split traffic by MAC address in LAN.
- [x] Support to split traffic with invert match rules.
- [x] Support to automatically switch nodes according to policy. That is to say, support to automatically test independent TCP/UDP/IPv4/IPv6 latencies, and then use the best nodes for corresponding traffic according to user-defined policy.
- [x] **`fixed_fallback` policy**: Prefer a specific node with automatic retry, grace period, and latency-aware fallback on failure. Recovers automatically when the preferred node comes back online.
- [x] Support advanced DNS resolution process.
- [x] Support full-cone NAT for shadowsocks, trojan(-go) and socks5 (no test).
- [x] Support various trending proxy protocols, seen in [proxy-protocols.md](./docs/en/proxy-protocols.md).

## Getting Started

Please refer to [Quick Start Guide](./docs/en/README.md) to start using `dae` right away!

## Dialer Selection Policies

dae supports several dialer (node) selection policies for `group` blocks:

| Policy | Description |
|--------|-------------|
| `fixed(index)` | Always use the node at the given index. No fallback |
| `min_moving_avg` | Pick the node with the lowest moving-average latency |
| `min_avg10` | Pick the node with the lowest average latency over the last 10 probes |
| `min_last_latency` | Pick the node with the lowest most-recent latency |
| `random` | Pick a random alive node |
| **`fixed_fallback(index, timeout, retries, fallback_policy)`** | **Fixed node with disaster-recovery fallback** |

### `fixed_fallback` — Fixed Node with Graceful Degradation

The `fixed_fallback` policy always prefers a specific node but gracefully degrades to a backup policy when that node dies, and **automatically returns** when it recovers.

**Syntax:** `fixed_fallback(index, timeout, retries, fallback_policy)`

| Param | Default | Description |
|-------|---------|-------------|
| `index` | — (required) | Dialer index in group (0-based) |
| `timeout` | `3s` | Retry interval. Clamped to minimum 2s with WARN log |
| `retries` | `3` | Max retries before fallback. `0` = immediate fallback |
| `fallback_policy` | `min_moving_avg` | Policy after retries exhausted |

**How it works (two-layer architecture):**

```
                    ┌─ MustGetAlive=true  ── Use fixed node
                    │
  Select() ─────────┤
                    │                              Natural Traffic
                    │                                    ↓
                    └─ MustGetAlive=false ── → Fallback to backup node
                                               │
                                               ├─ Background goroutine drives
                                               │  retry probes independently
                                               │  (ticker every `timeout`)
                                               │
                                               └─ Node recovers → auto switch back
```

- **Natural traffic** falls back **immediately** on dead node — zero timeout window wasted
- **Background goroutine** independently drives the retry cycle, not dependent on traffic
- **Health check** dead detection also starts the goroutine (via `aliveTransitionCallback`)
- **Node recovery** is detected in next health check cycle or goroutine probe — traffic returns instantly

**Example:**
```
group {
    name 'my-group'
    policy 'fixed_fallback(0, 3s, 3, random)'
    node 'jp-tokyo-premium'   # index 0 — preferred
    node 'us-west-cheap'      # index 1 — fallback candidate
    node 'sg-singapore'       # index 2 — fallback candidate
}
```
Behavior: Always use `jp-tokyo-premium`. If it dies, **immediately** use a random alive fallback. Background goroutine retries every 3s for 3 attempts. If node recovers during that time, traffic switches back immediately.

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
