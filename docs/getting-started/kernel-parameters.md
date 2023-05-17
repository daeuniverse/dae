# Configure Kernel Parameters

> **Note**
> Parameters will be automatically configured if `global.auto_config_kernel_parameter` is `true`.

If you set up dae as a router or other intermediate device and bind it to LAN interfaces, you need to adjust some linux kernel parameters to make everything work fine. By default, the latest Linux distributions have IP Forwarding `disabled`. In the case where we need to up a Linux router/gateway or a VPN server or simply a plain dial-in server, then we need to enable forwarding. Moreover, in order to keep our gateway position and keep correct downstream route table, we should disable `send-redirects`. Do the followings to adjust linux kernel parameters:

For every LAN interfaces you want to proxy:

```shell
export lan_ifname=docker0

sudo tee /etc/sysctl.d/60-dae-$lan_ifname.conf << EOF
net.ipv4.conf.$lan_ifname.forwarding = 1
net.ipv6.conf.$lan_ifname.forwarding = 1
net.ipv4.conf.$lan_ifname.send_redirects = 0
EOF
sudo sysctl --system
```

It is also recommended to enable IPv4 forward to avoid weird situations:

```shell
echo "net.ipv4.ip_forward = 1" | sudo tee /etc/sysctl.d/60-ip-forward.conf
sudo sysctl --system
```

Please modify `docker0` to your LAN interface.
