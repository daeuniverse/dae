# Routing Configuration for Gaming

DSCP allows network devices to prioritize tagged packets, ensuring that gaming traffic isn’t delayed by other data on the network. For gaming, where low latency and stable connections are critical, combine DSCP and VPN can help minimize these issues.

By using DSCP tagging and VPN tunnels for gaming traffic, this setup can achieve the following:

- Prioritize gaming traffic to reduce latency and jitter.
- Ensure secure data transmission, bypassing ISP throttling and traffic management.
- Adapt to various VPN protocols, making it versatile for different network environments.

### DAE Configuration (e.g., /etc/dae/config.dae)
This setup optimizes routing specifically for gaming, aiming to minimize latency and enhance speed by avoiding proxies and leveraging direct routes with fwmark. The configuration is designed to prioritize gaming traffic efficiently.

```
routing {            
    # Direct all gaming traffic for low latency
    # Set DSCP mark for prioritized gaming traffic
    dscp(8) -> direct(mark:0x800)
}

```

### OpenWRT Network Config  (e.g. /etc/config/network)
This example configures a WireGuard tunnel in OpenWRT to provide an optimized route for gaming traffic. Select the appropriate MTU value based on game requirements (e.g., CS2 requires MTU > 1300 for proper UDP Ping functionality).

```
config interface 'wg100'
    option proto 'wireguard'
    option private_key '[Client Private Key]'
    list addresses '10.7.0.2/24'
    list addresses 'fd42:42:42::2/64'
    option mtu '1420'

config wireguard_wg100
    option public_key '[Server Public Key]'
    option endpoint_host '[Your Server IP]'
    list allowed_ips '0.0.0.0/0'
    list allowed_ips '::/0'

# IPv4 Route for gaming traffic
config route
    option interface 'wg100'
    option target '0.0.0.0/0'
    option gateway '10.7.0.1'
    option table '114'

# IPv6 Route for gaming traffic
config route6
    option interface 'wg100'
    option target '::/0'
    option gateway 'fd42:42:42::1'
    option table '114'

# IPv4 Rule for gaming traffic using fwmark
config rule
    option lookup '114'
    option mark '0x800/0x800'

# IPv6 Rule for gaming traffic using fwmark
config rule6
    option lookup '114'
    option mark '0x800/0x800'
```

### OpenWRT Firewall Config (e.g. /etc/config/firewall)
This firewall configuration ensures that gaming traffic from a specific device (e.g., Gaming PC) is correctly translated within the VPN environment, both for IPv4 and IPv6.

```
# IPv4 NAT for gaming traffic
config nat
    option src 'vpn'
    option src_ip '[Gaming PC IPv4 Address]'
    option target 'SNAT'
    option snat_ip '10.7.0.2'
    option family 'ipv4'
    list proto 'all'

# IPv6 NAT for gaming traffic
config nat
    option src 'vpn'
    option src_ip '[Gaming PC IPv6 Address]'
    option target 'SNAT'
    option snat_ip 'fd42:42:42::2'
    option family 'ipv6'
    list proto 'all'

```
This configuration establishes low-latency, efficient routing for gaming traffic via a WireGuard tunnel, using fwmark to avoid proxy delays and enable direct connections for enhanced performance.