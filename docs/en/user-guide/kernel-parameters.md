# Configure Kernel Parameters

> **Note**
> These parameters are configured automatically when `global.auto_config_kernel_parameter` is `true`.

If dae acts as a router or another intermediate device and binds to LAN
interfaces, adjust the Linux kernel parameters below.

Independently of that option, dae changes these host parameters every time it
starts, because replies injected from its `daens` network namespace re-enter the
host through the `dae0` veth with a remote source address:
`net.ipv4.conf.all.rp_filter = 0`, `net.ipv4.conf.all.arp_filter = 0`, and on
`dae0` `rp_filter = 0`, `arp_filter = 0`, `accept_local = 1`, `disable_ipv6 = 0`
and `forwarding = 1`. Inside its `daens` namespace, not on the host, dae also
enables `net.ipv4.tcp_early_demux` and `net.ipv4.ip_early_demux` on a
best-effort basis.

Recent Linux distributions disable IP forwarding by default. Enable it when
setting up a router, gateway, VPN server, or dial-in server. Disable
`send_redirects` to keep dae as the gateway and preserve downstream routing tables.

## 1. Configure LAN Interfaces

For each LAN interface you want to proxy, replace `docker0` with the interface name:

```shell
export lan_ifname=docker0

sudo tee /etc/sysctl.d/60-dae-lan-$lan_ifname.conf << EOF
net.ipv4.conf.$lan_ifname.forwarding = 1
net.ipv6.conf.$lan_ifname.forwarding = 1
net.ipv4.conf.$lan_ifname.send_redirects = 0
EOF
sudo sysctl --system
```

## 2. Enable Global Forwarding

Enable global IPv4 and IPv6 forwarding to avoid unexpected behavior:

```shell
printf 'net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n' | sudo tee /etc/sysctl.d/60-ip-forward.conf
sudo sysctl --system
```

## 3. Configure WAN Interfaces

For WAN interfaces that accept router advertisements (RA), replace `eth0` with the interface name:

```shell
export wan_ifname=eth0

if [ "$(cat /proc/sys/net/ipv6/conf/$wan_ifname/accept_ra)" == "1" ]; then
    sudo tee /etc/sysctl.d/60-dae-wan-$wan_ifname.conf << EOF
net.ipv6.conf.$wan_ifname.accept_ra = 2
EOF
    sudo sysctl --system
fi
```

If `accept_ra` is `1`, change it to `2`: setting
`net.ipv6.conf.all.forwarding = 1` suppresses RA acceptance when `accept_ra` is `1`.
See <https://sysctl-explorer.net/net/ipv6/accept_ra/>.
