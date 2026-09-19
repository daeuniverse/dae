# Use external DNS

This page shows how to make an external resolver, AdGuardHome in the examples,
answer every DNS query that dae intercepts, while the resolver's own upstream
queries go out through dae and its proxies. The resolver can run on the dae
host or on another machine in the LAN. How dae intercepts DNS and how the
sniffed domain feeds back into routing is described in [DNS](dns.md) and
[how it works](../how-it-works.md).

## External DNS on the dae host

AdGuardHome runs on the dae host and resolves China mainland domains directly
and everything else through `dns.google`:

```
Listen on: the same machine with dae, port 53.

China mainland: udp://223.5.5.5:53
Others: https://dns.google/dns-query
```

Configure dae as follows:

1. Set `wan_interface` in the `global` section, so that AdGuardHome's own
   upstream queries leave the host through dae and can be proxied.

2. Insert the following rule at the start of the `routing` section. Without
   it, dae would intercept AdGuardHome's plain UDP queries to `223.5.5.5` and
   hand them back to AdGuardHome, which loops:

   ```python
   pname(AdGuardHome) && l4proto(udp) && dport(53) -> must_direct
   ```

   Keep a routing rule that sends `dns.google` through a proxy, so the DoH
   upstream is proxied.

3. Make AdGuardHome the upstream for every intercepted query in the `dns`
   section:

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

4. If you bind to WAN, point `/etc/resolv.conf` at a public resolver, for
   example `nameserver 119.29.29.29`, not at the local AdGuardHome. Queries to
   `127.0.0.1` stay on the loopback interface and never reach dae; queries to a
   public address leave through the NIC, where dae intercepts them and sends
   them to AdGuardHome through the `dns` section, so dae sees the answers.

   DNS services such as dnsmasq often overwrite `/etc/resolv.conf` after a
   reboot. If this happens, uninstall the service or run
   `sudo chattr +i /etc/resolv.conf`.

5. If you bind to LAN, a UDP query from a LAN client to the dae host's own port
   53 is routed like any other packet and then handed to the resolver configured
   in the `dns` section, so dae sees the answer and its `domain()` rules match
   that client's traffic too. Advertising the dae host as the DNS server in DHCP
   therefore works. If you want the host's own resolver to answer those queries
   instead of dae, express it as a routing rule, for example
   `l4proto(udp) && dport(53) && dip(<address of the dae host>) -> must_direct`.

6. If DNS still fails without warning or error logs, move AdGuardHome off port
   53. Another program on port 53 breaks interception on NICs that cannot
   disable checksum verification; see
   [#31](https://github.com/daeuniverse/dae/issues/31#issuecomment-1467358364).

7. If you use PVE, refer to [#37](https://github.com/daeuniverse/dae/discussions/37).

## External DNS on another LAN machine

AdGuardHome runs on another machine in the LAN:

```
Listen on: 192.168.30.3:53 (mac address: 8c:16:45:36:1c:5a)

China mainland: udp://223.5.5.5:53
Others: https://dns.google/dns-query
```

Configure dae as follows:

1. Set `lan_interface` in the `global` section, so that AdGuardHome's own
   upstream queries pass through dae and can be proxied.

2. Insert the following rule at the start of the `routing` section, for the
   same reason as on the dae host:

   ```python
   sip(192.168.30.3) && l4proto(udp) && dport(53) -> must_direct
   # Or use MAC address if in the same link:
   # mac('8c:16:45:36:1c:5a') && l4proto(udp) && dport(53) -> must_direct
   ```

   Keep a routing rule that sends `dns.google` through a proxy.

3. Make AdGuardHome the upstream for every intercepted query in the `dns`
   section:

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

4. Have the DHCP server advertise a public resolver, not the AdGuardHome
   machine, as the DNS server. A query sent straight to `192.168.30.3`
   normally travels over the LAN without passing dae, so dae does not see the
   answer; dae intercepts a query to any other address, answers it through
   AdGuardHome and sees the answer.

5. If DNS still fails without warning or error logs, move AdGuardHome off port
   53; see
   [#31](https://github.com/daeuniverse/dae/issues/31#issuecomment-1467358364).

6. If you use PVE, refer to [#37](https://github.com/daeuniverse/dae/discussions/37).
