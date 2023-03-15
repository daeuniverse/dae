# Quick Start Guide

## Linux Kernel Requirement

## Kernel Version

Use `uname -r` to check the kernel version on your machine.

> **Note**
> If you find your kernel version is `< 5.8`, follow the [**Upgrade Guide**](./kernel-upgrade.md) to upgrade the kernel to the minimum required version.

**Bind to LAN: >= 5.8**

You need bind dae to LAN interface, if you want to provide network service for LAN as an intermediate device.

This feature requires the kernel version of machine on which dae install >= 5.8.

Note that if you bind dae to LAN only, dae only provide network service for traffic from LAN, and not impact local programs.

**Bind to WAN: >= 5.8**

You need bind dae to WAN interface, if you want dae to provide network service for local programs.

This feature requires kernel version of the machine >= 5.8.

Note that if you bind dae to WAN only, dae only provide network service for local programs and not impact traffic coming in from other interfaces.

## Kernel Configurations

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

> **Note**
> `Armbian` users can follow the [**Upgrade Guide**](./kernel-upgrade.md) to upgrade the kernel to meet the kernel configuration requirement.

## Kernel Parameters

If you set up dae as a router or other intermediate device and bind it to LAN interfaces, you need to adjust some linux kernel parameters to make everything work fine. By default, the latest Linux distributions have IP Forwarding `disabled`. In the case where we need to up a Linux router/gateway or a VPN server or simply a plain dial-in server, then we need to enable forwarding. Moreover, in order to keep our gateway position and keep correct downstream route table, we should disable `send-redirects`. Do the followings to adjust linux kernel parameters:

```shell
export lan_ifname=docker0

sudo tee /etc/sysctl.d/60-dae-$lan_ifname.conf << EOF
net.ipv4.conf.$lan_ifname.forwarding = 1
net.ipv6.conf.$lan_ifname.forwarding = 1
net.ipv4.conf.$lan_ifname.send_redirects = 0
EOF
sudo sysctl --system
```

Please modify `docker0` to your LAN interface.

## Installation

### Archlinux/Manjaro

dae has been released on [AUR](https://aur.archlinux.org/packages/dae/).

```shell
# yay -S dae
pacman -S --needed git base-devel
git clone https://aur.archlinux.org/dae.git
cd dae
makepkg -si
```

After installation, use systemctl to control it.

```shell
# start dae
sudo systemctl start dae

# auto start dae at boot
sudo systemctl enable dae
```

### Docker

Pre-built image and related docs can be found at https://hub.docker.com/r/daeuniverse/dae.

Alternatively, you can use `docker compose`:

```shell
git clone --depth=1 https://github.com/daeuniverse/dae
docker compose up -d --build
```

### Others

Other users can build dae by scratch. See [Build Guide](build-by-yourself.md) for more help.

### Minimal Configuration

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
  wan_interface: wlp5s0

  log_level: info
  allow_insecure: false
}

subscription {
  # Fill in your subscription links here.
}

dns {
  upstream {
    googledns: 'tcp+udp://dns.google:53'
    alidns: 'udp://dns.alidns.com:53'
  }
  request {
    fallback: alidns
  }
  response {
    upstream(googledns) -> accept
    !qname(geosite:cn) && ip(geoip:private) -> googledns
    fallback: accept
  }
}

group {
  proxy {
    #filter: name(keyword: HK, keyword: SG)
    policy: min_moving_avg
  }
}

routing {
  pname(NetworkManager, systemd-resolved) -> direct
  dip(224.0.0.0/3, 'ff00::/8') -> direct

  ### Write your rules below.

  dip(geoip:private) -> direct
  dip(geoip:cn) -> direct
  domain(geosite:cn) -> direct

  fallback: proxy
}
```

See more at [example.dae](https://github.com/daeuniverse/dae/blob/main/example.dae).

If you use PVE, refer to [#37](https://github.com/daeuniverse/dae/discussions/37).