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

## Connectivity Check

dae supports configurable health checks for proxy nodes. The check behavior adapts to your configuration dynamically.

### Parameters

| Param | Default | Description |
|-------|---------|-------------|
| `tcp_check_url` | (not set) | URL for TCP connectivity check. Not set = skip TCP probes |
| `udp_check_dns` | (not set) | DNS server for UDP check. Not set = skip UDP probes |
| `check_interval` | 0 | Interval between checks. **0 = disabled** (no probes sent). Below **2s** clamped with WARN log |

### Dynamic Probe Selection

- **Protocol-independent IPv6 detection**: TCP and UDP IPv6 checks are evaluated independently based on their own address lists
- **Unconfigured = No probe**: If you only set `tcp_check_url`, UDP probes are skipped entirely
- **check_interval=0**: All checks disabled, WARN log confirms the user'\''s intention
- **Minimum 2s**: Values below 2s are clamped with a WARN log to prevent probe storms

### Examples

**Minimal (no health check):**
```
group {
    check_interval: 0
    tcp_check_url: '\''http://cp.cloudflare.com'\''  # ← ignored, check_interval=0 takes precedence
}
```

**TCP only (UDP skipped):**
```
group {
    tcp_check_url: '\''http://cp.cloudflare.com'\''
    # udp_check_dns not set → no UDP probes
    check_interval: 30s
}
```

**Full check:**
```
group {
    tcp_check_url: '\''http://cp.cloudflare.com'\''
    udp_check_dns: '\''dns.google:53'\''
    check_interval: 60s
}
```

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
