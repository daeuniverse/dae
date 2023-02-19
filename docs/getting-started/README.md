# Quick Start Guide

## Linux Kernel Requirement

### Kernel Version

Use `uname -r` to check the kernel version on your machine.

> **Notes**
> If you find your kernel version is `< 5.8`, follow the guide [HERE](./kernel-upgrade.md) to upgrade the kernel to the minimum required version.

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

**Bind to LAN**

```
CONFIG_DEBUG_INFO_BTF
```

**Bind to WAN**

```
CONFIG_DEBUG_INFO_BTF
```

Check them using command like:

```shell
(zcat /proc/config.gz || cat /boot/{config,config-$(uname -r)}) | grep 'CONFIG_DEBUG_INFO_BTF='
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
