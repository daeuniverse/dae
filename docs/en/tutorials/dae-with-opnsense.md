# dae with OPNsense: Best Practices

Run dae on a separate Linux system connected to OPNsense through Ethernet,
a Linux bridge, or SR-IOV to use it in a bypass setup.

## Interfaces

Assign the interface between dae and OPNsense an address in a different subnet
from OPNsense's LAN. For an interface named `wan_proxy`, use:

```
OPN LAN: 192.168.1.1/24
OPN wan_proxy: 192.168.2.2 Gateway Auto Detect
dae enp1s0: 192.168.2.1 Gateway 192.168.2.2
```

## Traffic Splitting

1. Configure the GeoIP list.

   Add it in `Firewall: Aliases: GeoIP Settings`. See the [OPNsense documentation](https://docs.opnsense.org/manual/how-tos/maxmind_geo_ip.html).

2. Configure the GeoIP alias.

   In `Firewall: Aliases: Aliases`, add `proxyip` with type GeoIP. Select China under Asia, or your own country.

3. Add an IP address list (optional).

   In `Firewall: Aliases: Aliases`, add `proxyip_ex` with type URL Table. Use a link to a maintained list with one IP address in CIDR notation per line.

4. Configure the reserved-address alias.

   In `Firewall: Aliases: Aliases`, add `__private_network` with type Network. Include all reserved addresses, or only those used in your network. See [Reserved IP Addresses](https://www.wikiwand.com/zh-hant/保留IP地址).

5. Combine the aliases.

   In `Firewall: Aliases: Aliases`, add `proxyroute` with type Network group. Select `proxyip`, `proxyip_ex` (if used), `__private_network`, and the built-in `__lo0_network` alias.

6. Add the gateway.

   In `System: Gateways: Single`, add `proxy` on `wan_proxy`, the interface connected to dae. Use dae's IP address: `192.168.2.1` in the example above.

   Give it a lower priority than the default gateway. For example, if the default gateway is set to 254, set this gateway to 255.

7. Configure traffic splitting.

   In `Firewall: Rules: Floating`, add a rule with these settings:

   | Item | Configuration |
   | - | - |
   | Action | Pass |
   | Quick | √ |
   | Interface | LAN |
   | Direction | in |
   | TCP/IP Version | IPv4 |
   | Protocol | TCP/UDP |
   | Destination/Invert | √ |
   | Destination | proxyroute |
   | Gateway | proxy |

   To exclude LAN devices from dae, use Source/Invert.

8. Allow dae traffic into OPNsense.

   Create a rule in `Firewall: Rules: wan_proxy`, keep the defaults, and save it.

9. Proxy OPNsense's own traffic (optional).

   To proxy OPNsense traffic, such as configuration backups to Google Drive, add a static route in `System: Routes: Configuration`. Set the gateway to `proxy` for the IP range that needs proxying.

   Do not handle WAN traffic in floating rules; this can cause loops.

## dae Configuration

The following settings route DNS requests through dae and address cases where
proxy connections work but direct connections fail. They do not cover dae's
configuration file. For `domain` and `ip` modes and the `dns` and `routing`
rules, refer to the dae documentation.

In `domain` and `domain+` modes, DNS requests must pass through dae for the
kernel-side `domain()` rules to match. By default dae opens no DNS listener,
so pointing the DNS server at dae's address does not work. To use dae as a
DNS server instead, set `dns { bind: '192.168.2.1:53' }`: a bare `ip:port`
listens on UDP only, and `tcp+udp://192.168.2.1:53` listens on both. Queries
received on that listener use the same `dns` rules and cache.

If DNS requests cannot pass through dae, `domain` mode still matches routing
rules again with the sniffed domain for connections the kernel sent to a proxy
outbound. dae does so only after it confirms the domain, from its DNS cache or
from a background probe through `bootstrap_resolver` (default `119.29.29.29:53`
and `223.5.5.5:53`). The first connection to an unknown domain keeps the
kernel's IP-based decision; dae matches routing rules again for later
connections. `domain+` never matches routing rules again. `domain++` matches
routing rules again with every sniffed domain without confirming it and is less
performant than `domain` mode. No mode matches routing rules again for
connections the kernel already sent to `direct` or `block`. If you use
`domain++`, or `ip` mode without domain-based splitting, skip the DNS
configuration below.

1. Configure DNS forwarding.

   In `Services: Unbound DNS: Query Forwarding`, forward requests to a server such as OpenDNS at `208.67.222.222`.

   The next step routes this address through dae. Do not use the DNS server supplied by your upstream: keeping it separate lets you query that server with `dig` or `nslookup` when troubleshooting.

2. Configure a static route.

   In `System: Routes: Configuration`, add a route for `208.67.222.222/32` with gateway `proxy`.

DNS requests now pass through dae for interception. The configured DNS server
is not the final query destination: dae rewrites it according to the `dns`
rules before sending the request.

Unbound appends EDNS parameters when forwarding client requests. dae reads
upstream UDP responses into a 65536-byte buffer, so large EDNS responses arrive
intact. For `udp://` and `tcp+udp://` upstreams, dae retries a response with
`TC=1` over TCP. When a response to a client exceeds the UDP size the client
advertised in EDNS0, or 512 bytes when the query carries no EDNS0, dae
truncates it and sets `TC=1` so the client retries over TCP.

Switching to Dnsmasq or disabling EDNS in Unbound is therefore not required.
To disable EDNS anyway, disable DNSSEC support in
`Services: Unbound DNS: General` and add the following Unbound configuration:

``` yaml
# saved as /usr/local/etc/unbound.opnsense.d/disableedns.conf
server:
    disable-edns-do: yes 
```

dae does not perform SNAT. If proxied connections work but direct connections
fail, configure NAT on the system running dae.

Here, "direct" means the `direct` outbound in dae's `routing`, not traffic that
OPNsense sends straight to WAN without dae. For example, OPNsense may route
Steam traffic through dae, where `domain(geosite:steam@cn) -> direct` is
configured, yet Steam cannot log in or download.

## Performance Optimization

Increasing the MTU between OPNsense and dae from 1500 to 9000 can reduce load.
Change both interfaces and the intermediate link.
