# Working Principle of dae

[**简体中文**](../zh/how-it-works.md) | [**English**](./how-it-works.md)

dae operates by loading a program into the tc (traffic control) mount point in the Linux kernel using [eBPF](https://en.wikipedia.org/wiki/EBPF). This program performs traffic splitting before the traffic enters the TCP/IP network stack. The position of tc in the Linux network protocol stack is illustrated in the diagram below (the diagram illustrates the receiving path, while the sending path is in the opposite direction), where netfilter represents the location of iptables/nftables.

![Network Stack Path](../netstack-path.webp)

## Traffic Splitting Principle

### Splitting Criteria

dae supports traffic splitting based on domain name, source IP, destination IP, source port, destination port, TCP/UDP, IPv4/IPv6, process name, MAC address, and other factors.

Among these, source IP, destination IP, source port, destination port, TCP/UDP, IPv4/IPv6, and MAC address can be obtained by parsing MACv2 frames.

The **process name** is obtained by monitoring local process socket, connect, and sendmsg system calls in the cgroupv2 mount point. It then reads and parses the command line from the process control block. This method is significantly faster than user-space programs like Clash that scan the entire procfs to obtain process information (the latter might take even tens of milliseconds).

The **domain name** is obtained by intercepting DNS requests and associating the requested domain name with the corresponding IP address. However, this method has some potential issues:

1. It might lead to misjudgment. For example, if a domestic and a foreign website sharing the same IP address are accessed simultaneously within a short period, or if the browser employs DNS caching.
2. The user's DNS requests must traverse dae. This can be achieved by setting dae as the DNS server or using a public DNS while dae serves as the gateway.

Despite these challenges, this approach is already an optimal solution compared to other methods. For instance, the Fake IP approach cannot perform IP-based splitting and is plagued by severe cache pollution issues. Similarly, domain sniffing can only intercept traffic like TLS/HTTP. While SNI sniffing for traffic splitting is effective, eBPF's limitations on program complexity and its lack of support for loops prevent us from implementing domain sniffing in the kernel space.

Hence, if DNS requests cannot pass through dae, domain-based splitting will not succeed.

> To mitigate DNS pollution and achieve improved CDN connection speeds, dae employs domain sniffing in user space. When `dial_mode` is set to "domain" or its variants and proxied traffic needs to be processed, dae sends the sniffed domain to the proxy server instead of sending the IP address. Consequently, the proxy server re-resolves the domain and connects using the optimal IP. This approach addresses DNS pollution and enhances CDN connection speed.
>
> Additionally, advanced users who have used alternative splitting solutions and don't wish to route DNS requests through dae but still want certain traffic to be split based on domain (e.g., splitting traffic to Netflix nodes and download nodes based on the target domain, with some directly connecting via the core) can enforce the use of sniffed domains for splitting by setting `dial_mode: domain++`.

dae achieves traffic splitting by redirecting traffic using the program in the tc mount point. The redirection is based on the splitting result, either redirecting the traffic to dae's tproxy port or allowing it to bypass dae and go directly.

### Proxy Mechanism

The proxy mechanism of dae is akin to other programs. However, when binding to the LAN interface, dae leverages eBPF to directly associate the socket buffer of the traffic to be proxied in the tc mount point with the socket of dae's tproxy listening port. While binding to the WAN interface, dae transfers the socket buffer of the traffic to be proxied from the egress queue of the network card to the ingress queue. It also disables checksums and modifies the destination address to the tproxy listening port.

In terms of benchmarking, dae's proxy performance slightly surpasses that of other proxy programs, but the difference is not significant.

As of [PR:implement stack bypass](https://github.com/daeuniverse/dae/pull/458), the hijack datapath has been changed to bypass stack for better performance and less stack influence (e.g. netfilter, systemd-sysctl). Please refer to the PR description for better understanding.

### Direct Connection Mechanism

Conventionally, traffic splitting involves passing traffic through a proxy program, navigating the splitting module, and then determining whether to use a proxy or establish a direct connection. This process requires parsing, processing, and copying traffic through the network stack, delivering it to the proxy program, and subsequently copying, processing, and encapsulating it through the network stack before sending it out. This consumes substantial resources. Particularly in scenarios like BitTorrent downloads, even if a direct connection is set, it still consumes numerous connections, ports, memory, and CPU resources. It might even impact NAT type in gaming situations due to the proxy program's inadequate handling, resulting in connection errors.

dae performs traffic splitting at an earlier kernel stage, forwarding directly connected traffic through layer 3 routing. This approach reduces overhead by minimizing transitions between kernel and user space. At this point, Linux functions as a pure switch or router.

> For effective direct connection, advanced users with specific network topologies should ensure that, after configuring the [kernel parameters](user-guide/kernel-parameters.md) and **disabling** dae, other devices can access the network normally when the device with dae is set as the gateway. For instance, accessing 223.5.5.5 should yield a "UrlPathError" response. When performing tcpdump on the dae-equipped device, request packets from client devices should be visible.

Consequently, dae does not perform SNAT for directly connected traffic. In setups with a "side-router," this leads to asymmetric routing. In this scenario, when sent out, traffic from client devices passes through dae to the gateway, but when received, traffic goes directly from the gateway to client devices, bypassing dae.

> Here, "side-router" refers to: 1) functioning as the gateway, 2) performing SNAT on TCP/UDP, and 3) having the LAN and WAN interfaces in the same network segment.
>
> For example, if a laptop is at 192.168.0.3, the side-router is at 192.168.0.2, and the router is at 192.168.0.1, the logical three-layer topology would be: laptop -> side-router -> router. On the router side, only TCP/UDP traffic with a source IP of 192.168.0.2 would be visible, and no TCP/UDP traffic with a source IP of 192.168.0.3 would be present.
>
> To our knowledge, we are the pioneers of this "side-router" definition (laughter).

Asymmetric routing brings an advantage and a potential issue:

1. It can enhance performance. Since return traffic doesn't traverse dae, direct connection performance becomes as swift as without a side-router, reducing the path.
2. It might disrupt stateful firewall's state maintenance and lead to packet loss (e.g., Sophos Firewall). However, this issue generally doesn't occur in home networks.

From a benchmark perspective, dae's direct connectivity performance is formidable compared to other proxy solutions.
