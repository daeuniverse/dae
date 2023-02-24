# dae

<img src="https://github.com/v2rayA/dae/blob/main/logo.png" border="0" width="25%">

**_dae_**, means goose, is a lightweight and high-performance transparent proxy solution.

In order to improve the traffic split performance as much as possible, dae runs the transparent proxy and traffic split suite in the linux kernel by eBPF. Therefore, dae has the opportunity to make the direct traffic bypass the forwarding by proxy application and achieve true direct traffic through. Under such a magic trick, there is almost no performance loss and additional resource consumption for direct traffic.

As a successor of [v2rayA](https://github.com/v2rayA/v2rayA), dae abandoned v2ray-core to meet the needs of users more freely.

**Features**

1. Implement `Real Direct` traffic split (need ipforward on) to achieve [high performance](https://docs.google.com/spreadsheets/d/1UaWU6nNho7edBNjNqC8dfGXLlW0-cm84MM7sH6Gp7UE/edit?usp=sharing).
1. Support to split traffic by process name in local host.
1. Support to split traffic by MAC address in LAN.
1. Support to split traffic with invert match rules.
1. Support to automatically switch nodes according to policy. That is to say, support to automatically test independent TCP/UDP/IPv4/IPv6 latencies, and then use the best nodes for corresponding traffic according to user-defined policy.
1. Support advanced DNS resolution process.
1. Support full-cone NAT for shadowsocks, trojan(-go) and socks5 (no test).

## Prerequisites

### Kernel Version

Use `uname -r` to check the kernel version on your machine.

**Bind to LAN: >= 5.8**

You need bind dae to LAN interface, if you want to provide network service for LAN as an intermediate device.

This feature requires the kernel version of machine on which dae install >= 5.8.

Note that if you bind dae to LAN only, dae only provide network service for traffic from LAN, and not impact local programs.

**Bind to WAN: >= 5.8**

You need bind dae to WAN interface, if you want dae to provide network service for local programs.

This feature requires kernel version of the machine >= 5.8.

Note that if you bind dae to WAN only, dae only provide network service for local programs and not impact traffic coming in from other interfaces.

### Kernel Configuration Item

Usually, mainstream desktop distributions have these items turned on. But in order to reduce kernel size, some items are turned off by default on embedded device distributions like OpenWRT, Armbian, etc.

Use following command to show kernel configuration items on your machine.

```shell
zcat /proc/config.gz || cat /boot/{config,config-$(uname -r)}
```

dae needs:
```
CONFIG_DEBUG_INFO_BTF=y
CONFIG_NET_CLS_ACT=y
CONFIG_NET_SCH_INGRESS=m
CONFIG_NET_INGRESS=y
CONFIG_NET_EGRESS=y
```
Check them using command like:

```shell
(zcat /proc/config.gz || cat /boot/{config,config-$(uname -r)}) | grep -E 'CONFIG_(DEBUG_INFO_BTF|NET_CLS_ACT|NET_SCH_INGRESS|NET_INGRESS|NET_EGRESS)='
```

### Enable IP Forwarding

By default, any latest Linux distributions will have IP Forwarding `disabled`. In the case where we need to up a Linux router/gateway or a VPN server or simply a plain dial-in server, then we must need to enable forwarding. Do the followings to have `ip-forwarding` feature enabled:

```shell
sudo tee /etc/sysctl.d/dae.conf<<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
sudo sysctl --system
```

## Getting Started

Please refer to [Quick Start Guide](./docs/getting-started/README.md) to start using `dae` right away!

## Known Issues

1. If you setup dae and also a shadowsocks server (or any UDP servers) on the same machine in public network, such as a VPS, don't forget to add `sport(your server ports) -> must_direct` rule for your UDP server port. Because states of UDP are hard to maintain, all outgoing UDP packets will potentially be proxied (depends on your routing), including traffic to your client. This is not what we want to see. `must_direct` means all traffic including DNS traffic will be direct.

## TODO

- [ ] Automatically check dns upstream and source loop (whether upstream is also a client of us) and remind the user to add sip rule.
- [ ] MACv2 extension extraction.
- [ ] Log to userspace.
- [ ] Protocol-oriented node features detecting (or filter), such as full-cone (especially VMess and VLESS).
- [ ] Add quick-start guide
- [ ] ...
