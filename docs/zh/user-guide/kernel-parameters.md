# 配置内核参数

> **注意**
> 如果 `global.auto_config_kernel_parameter` 为 `true`，将自动配置参数。

将 dae 所在设备作为路由器或其他中间设备，并绑定 LAN 接口时，需要调整 Linux 内核参数。

无论该选项是否开启，dae 每次启动都会修改以下主机参数：`net.ipv4.conf.all.rp_filter = 0`、`net.ipv4.conf.all.arp_filter = 0`，以及 `dae0` 上的 `rp_filter = 0`、`arp_filter = 0`、`accept_local = 1`、`disable_ipv6 = 0`、`forwarding = 1`。原因是从它的 `daens` 网络命名空间注入的回复会经 `dae0` veth 以远端源地址重新进入主机。它还会在自己的 `daens` 命名空间内（而非主机上）尽力启用 `net.ipv4.tcp_early_demux` 和 `net.ipv4.ip_early_demux`。

较新的 Linux 发行版默认禁用 IP 转发。搭建 Linux 路由器、网关、VPN 服务器或普通拨入服务器时，需要启用转发。还应禁用 `send_redirects`，以保持设备的网关角色及正确的下游路由表。

## 1. 配置 LAN 接口

对每个需要代理的 LAN 接口执行以下操作，将 `docker0` 替换为接口名称：

```shell
export lan_ifname=docker0

sudo tee /etc/sysctl.d/60-dae-lan-$lan_ifname.conf << EOF
net.ipv4.conf.$lan_ifname.forwarding = 1
net.ipv6.conf.$lan_ifname.forwarding = 1
net.ipv4.conf.$lan_ifname.send_redirects = 0
EOF
sudo sysctl --system
```

## 2. 启用全局转发

启用全局 IPv4 和 IPv6 转发，以避免异常情况：

```shell
printf 'net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n' | sudo tee /etc/sysctl.d/60-ip-forward.conf
sudo sysctl --system
```

## 3. 配置 WAN 接口

对于接受路由器通告（RA）的 WAN 接口，将 `eth0` 替换为接口名称：

```shell
export wan_ifname=eth0

if [ "$(cat /proc/sys/net/ipv6/conf/$wan_ifname/accept_ra)" == "1" ]; then
    sudo tee /etc/sysctl.d/60-dae-wan-$wan_ifname.conf << EOF
net.ipv6.conf.$wan_ifname.accept_ra = 2
EOF
    sudo sysctl --system
fi
```

`net.ipv6.conf.all.forwarding = 1` 会抑制 `accept_ra = 1` 时的 RA 接收，因此需要将 `accept_ra` 从 `1` 改为 `2`。参阅 <https://sysctl-explorer.net/net/ipv6/accept_ra/>。
