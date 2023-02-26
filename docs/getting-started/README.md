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

## Usage

### Build

**Make Dependencies**

```shell
clang >= 10
llvm >= 10
golang >= 1.18
make
```

**Build**

```shell
git clone https://github.com/v2rayA/dae.git
cd dae
git submodule update --init
# Minimal dependency build:
make GOFLAGS="-buildvcs=false" CC=clang
# Or normal build:
# make
```

### Run

**Runtime Dependencies**

For traffic splitting, dae relies on the following data sources, [geoip.dat](https://github.com/v2ray/geoip/releases/latest) and [geosite.dat](https://github.com/v2fly/domain-list-community/releases/latest).

```shell
mkdir -p /usr/local/share/dae/
pushd /usr/local/share/dae/
curl -L -o geoip.dat https://github.com/v2ray/geoip/releases/latest/download/geoip.dat
curl -L -o geosite.dat https://github.com/v2ray/domain-list-community/releases/latest/download/dlc.dat
popd
```

**Run**

Download the example config file:
```shell
curl -L -o example.dae https://github.com/v2rayA/dae/raw/main/example.dae
```
See [example.dae](https://github.com/v2rayA/dae/blob/main/example.dae).

After fine tuning, run dae:
```shell
./dae run -c example.dae
```

Alternatively, you may run dae as a daemon(systemd) service. Check out more details [HERE](./run-as-daemon.md).

