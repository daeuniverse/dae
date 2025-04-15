# Quick Start Guide

[**简体中文**](../zh/README.md) | [**English**](README.md)

## Linux Kernel Requirement

## Kernel Version

Use `uname -r` to check the kernel version on your machine.

> **Note**
> If you find your kernel version is `< 5.17`, follow the [**Upgrade Guide**](user-guide/kernel-upgrade.md) to upgrade the kernel to the minimum required version.

`Bind to LAN: >= 5.17`

You need bind dae to LAN interface, if you want to provide network service for LAN as an intermediate device.

This feature requires the kernel version of machine on which dae install >= 5.17.

Note that if you bind dae to LAN only, dae only provide network service for traffic from LAN, and not impact local programs.

`Bind to WAN: >= 5.17`

You need bind dae to WAN interface, if you want dae to provide network service for local programs.

This feature requires kernel version of the machine >= 5.17.

Note that if you bind dae to WAN only, dae only provide network service for local programs and not impact traffic coming in from other interfaces.

`Use trace command`

If you want to use `dae trace` command to triage network connectivity issue, the kernel version is required to be >= 5.15.

## Kernel Configurations

Usually, mainstream desktop distributions have these items turned on. But in order to reduce kernel size, some items are turned off by default on embedded device distributions like OpenWRT, Armbian, etc.

Use following command to show kernel configuration items on your machine.

```shell
zcat /proc/config.gz || cat /boot/{config,config-$(uname -r)}
```

dae needs:

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_CGROUPS=y
CONFIG_KPROBES=y
CONFIG_NET_INGRESS=y
CONFIG_NET_EGRESS=y
CONFIG_NET_SCH_INGRESS=m
CONFIG_NET_CLS_BPF=m
CONFIG_NET_CLS_ACT=y
CONFIG_BPF_STREAM_PARSER=y
CONFIG_DEBUG_INFO=y
# CONFIG_DEBUG_INFO_REDUCED is not set
CONFIG_DEBUG_INFO_BTF=y
CONFIG_KPROBE_EVENTS=y
CONFIG_BPF_EVENTS=y
```

Check them using command like:

for bash and other POSIX compliant shell:

```shell
(zcat /proc/config.gz || cat /boot/{config,config-$(uname -r)}) | grep -E 'CONFIG_(DEBUG_INFO|DEBUG_INFO_BTF|KPROBES|KPROBE_EVENTS|BPF|BPF_SYSCALL|BPF_JIT|BPF_STREAM_PARSER|NET_CLS_ACT|NET_SCH_INGRESS|NET_INGRESS|NET_EGRESS|NET_CLS_BPF|BPF_EVENTS|CGROUPS)=|# CONFIG_DEBUG_INFO_REDUCED is not set'
```

for fish shell:

```fish
begin; zcat /proc/config.gz || bat /boot/config "/boot/config-"(uname -r); end | grep -E 'CONFIG_(DEBUG_INFO|DEBUG_INFO_BTF|KPROBES|KPROBE_EVENTS|BPF|BPF_SYSCALL|BPF_JIT|BPF_STREAM_PARSER|NET_CLS_ACT|NET_SCH_INGRESS|NET_INGRESS|NET_EGRESS|NET_CLS_BPF|BPF_EVENTS|CGROUPS)=|# CONFIG_DEBUG_INFO_REDUCED is not set'
```

> **Note**: `Armbian` users can follow the [**Upgrade Guide**](user-guide/kernel-upgrade.md) to upgrade the kernel to meet the kernel configuration requirement.

> `Arch Linux ARM` users can use [linux-aarch64-7ji](https://github.com/7Ji-PKGBUILDs/linux-aarch64-7ji) which meets the kernel configuration requirement of dae.

## Installation

### Arch Linux / Manjaro

dae has been released on [AUR](https://aur.archlinux.org/packages/dae) and [archlinuxcn](https://github.com/archlinuxcn/repo/tree/master/archlinuxcn/dae).

#### AUR

##### Latest Release (Optimized Binary for x86-64 v3 / AVX2)

```shell
[yay/paru] -S dae-avx2-bin
```

##### Latest Release (General x86-64 or aarch64)

```shell
[yay/paru] -S dae
```

##### Latest Git Version

```shell
[yay/paru] -S dae-git
```

#### archlinuxcn

##### Latest Release (Optimized Binary for x86-64 v3 / AVX2)

```shell
sudo pacman -S dae-avx2-bin
```

##### Latest Release (General x86-64 or aarch64)

```shell
sudo pacman -S dae
```

##### Latest Git Version

```shell
sudo pacman -S dae-git
```

After installation, use systemctl to control it.

```shell
# start dae
sudo systemctl start dae

# auto start dae at boot
sudo systemctl enable dae
```

### Gentoo Linux

dae has been released on [gentoo-zh](https://github.com/microcai/gentoo-zh)

use `app-eselect/eselect-repository` to enable this overlay:

```shell
eselect repository enable gentoo-zh
emaint sync -r gentoo-zh
emerge -a net-proxy/dae
```

### Fedora

dae has been released on [Fedora Copr](https://copr.fedorainfracloud.org/coprs/zhullyb/v2rayA/package/dae).

```shell
sudo dnf copr enable zhullyb/v2rayA
sudo dnf install dae
```

### Alpine

See [run on alpine](tutorials/run-on-alpine.md).

### macOS

We provide a hacky way to run dae on your macOS. See [run on macOS](tutorials/run-on-macos.md).

### Docker

Pre-built image and related docs can be found at <https://hub.docker.com/r/daeuniverse/dae>.

Alternatively, you can use `docker compose`:

```shell
git clone --depth=1 https://github.com/daeuniverse/dae
docker compose up -d --build
```

## Manual installation

> **Note**: This approach is **ONLY** recommended for `advanced` users. With this approach, users may have flexibility to test various versions of dae. Noted that newly introduced features are sometimes buggy, do it at your own risk.

dae can run as a daemon (systemd) service. See [run-as-daemon](user-guide/run-as-daemon.md)

### Installation Script

See [daeuniverse/dae-installer](https://github.com/daeuniverse/dae-installer) (or [mirror](https://hubmirror.v2raya.org/daeuniverse/dae-installer)).

### Build from scratch

See [Build Guide](user-guide/build-by-yourself.md).

## Minimal Configuration

For minimal bootable config:

```shell
global{}
routing{}
```

However, this config leaves dae no-load state. If you want dae to be in working state, following is a best practice for small config:

```shell
global {
  # Bind to LAN and/or WAN as you want. Replace the interface name to your own.
  #lan_interface: docker0
  wan_interface: auto # Use "auto" to auto detect WAN interface.

  log_level: info
  allow_insecure: false
  auto_config_kernel_parameter: true
}

subscription {
  # Fill in your subscription links here.
}

# See https://github.com/daeuniverse/dae/blob/main/docs/en/configuration/dns.md for full examples.
dns {
  upstream {
    googledns: 'tcp+udp://dns.google:53'
    alidns: 'udp://dns.alidns.com:53'
  }
  routing {
    request {
      qtype(https) -> reject
      fallback: alidns
    }
    response {
      upstream(googledns) -> accept
      ip(geoip:private) && !qname(geosite:cn) -> googledns
      fallback: accept
    }
  }
}

group {
  proxy {
    #filter: name(keyword: HK, keyword: SG)
    policy: min_moving_avg
  }
}

# See https://github.com/daeuniverse/dae/blob/main/docs/en/configuration/routing.md for full examples.
routing {
  pname(NetworkManager) -> direct
  dip(224.0.0.0/3, 'ff00::/8') -> direct

  ### Write your rules below.

  # Disable h3 because it usually consumes too much cpu/mem resources.
  l4proto(udp) && dport(443) -> block
  dip(geoip:private) -> direct
  dip(geoip:cn) -> direct
  domain(geosite:cn) -> direct

  fallback: proxy
}
```

See more at [example.dae](https://github.com/daeuniverse/dae/blob/main/example.dae).

If you use PVE, refer to [#37](https://github.com/daeuniverse/dae/discussions/37).

## PPPoE Interface
If you want to proxy PPPoE interface, please set wan/lan_interface to the interface generated by pppd (i.e., ppp0 / pppoe-wan) instead of the physical interface.
If you just using PPPoE interface for wan, simply set wan_interface to "auto".

## Reload and suspend

When the configuration changes, it is convenient to use command to hot reload the configuration, and the existing connection will not be interrupted in the process. When you want to suspend dae, you can use command to pause.

See [Reload and suspend](user-guide/reload-and-suspend.md).

## Troubleshooting

See [Troubleshooting](troubleshooting.md).
