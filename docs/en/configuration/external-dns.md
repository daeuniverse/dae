# Use external DNS

Pass DNS requests through dae for full domain-based routing. The kernel-side
`domain()` rules match only when dae has seen the DNS answer. In the default
`dial_mode: domain`, dae also re-matches the routing rules with the sniffed
domain for a connection the kernel sent to a proxy outbound. dae re-matches
only once the DNS answer passed through dae or the background probe through
`bootstrap_resolver` (default `119.29.29.29:53` and `223.5.5.5:53`) confirmed
the domain. The first connection to an unknown domain keeps the IP-based
decision. dae never re-matches traffic the kernel sent to `direct` or `block`.
`domain++` re-matches every sniffed connection without that check; `domain+`
never re-matches. Use the following configuration with an external DNS service
such as AdGuardHome.

## External DNS on localhost

To proxy queries to `dns.google` from a local external DNS service, use the following AdGuardHome configuration:

```
Listen on: the same machine with dae, port 53.

China mainland: udp://223.5.5.5:53
Others: https://dns.google/dns-query
```

Configure dae as follows:

1. Set `wan_interface` in the `global` section to proxy AdGuardHome's requests.

2. Insert the following rule at the start of the `routing` section to avoid loops:

   ```python
   pname(AdGuardHome) && l4proto(udp) && dport(53) -> must_direct
   ```

   Make sure the routing rules proxy `dns.google`.

3. Add the upstream and request routing to the `dns` section:

   ```
   dns {
     upstream {
       adguardhome: 'udp://127.0.0.1:53'
     }
     routing {
       request {
         fallback: adguardhome
       }
     }
   }
   ```

4. If you bind to WAN, make sure `/etc/resolv.conf` does not use your local external DNS service directly. For example, set `nameserver 119.29.29.29` so dae intercepts DNS traffic as packets pass through the NIC.

   DNS services such as dnsmasq often overwrite `/etc/resolv.conf` after a reboot. If this happens, uninstall the service or run `sudo chattr +i /etc/resolv.conf`.

5. If you bind to LAN, configure your DHCP server to advertise dae as the DNS server. The kernel-side `domain()` rules match only when DNS requests pass through dae.

6. If DNS issues persist without warning or error logs, change AdGuardHome's listening port from 53 to another port. See [#31](https://github.com/daeuniverse/dae/issues/31#issuecomment-1467358364).

7. If you use PVE, refer to [#37](https://github.com/daeuniverse/dae/discussions/37).

## External DNS on another LAN machine

To proxy queries to `dns.google` from an external DNS service on another LAN machine, use the following AdGuardHome configuration:

```
Listen on: 192.168.30.3:53 (mac address: 8c:16:45:36:1c:5a)

China mainland: udp://223.5.5.5:53
Others: https://dns.google/dns-query
```

Configure dae as follows:

1. Set `lan_interface` in the `global` section to proxy AdGuardHome's requests.

2. Insert the following rule at the start of the `routing` section to avoid loops:

   ```python
   sip(192.168.30.3) && l4proto(udp) && dport(53) -> must_direct
   # Or use MAC address if in the same link:
   # mac('8c:16:45:36:1c:5a') && l4proto(udp) && dport(53) -> must_direct
   ```

   Make sure the routing rules proxy `dns.google`.

3. Add the upstream and request routing to the `dns` section:

   ```
   dns {
     upstream {
       adguardhome: 'udp://192.168.30.3:53'
     }
     routing {
       request {
         fallback: adguardhome
       }
     }
   }
   ```

4. If you bind to LAN, configure your DHCP server to advertise dae as the DNS server. The kernel-side `domain()` rules match only when DNS requests pass through dae.

5. If DNS issues persist without warning or error logs, change AdGuardHome's listening port from 53 to another port. See [#31](https://github.com/daeuniverse/dae/issues/31#issuecomment-1467358364).

6. If you use PVE, refer to [#37](https://github.com/daeuniverse/dae/discussions/37).
