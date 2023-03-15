# Use External DNS

> **Note**
> DNS request should be forwarded by dae for domain based traffic split. This guide will show you how to configure dae with external DNS.

If you use a external DNS like AdguardHome, you could refer to the following guide.

## External DNS on localhost

If you set up a external DNS on localhost, you may want to let the DNS queries to dns.google proxied. For example, if you have following configuration in AdguardHome:

```
Listen on: the same machine with dae, port 53.

China mainland: udp://223.5.5.5:53
Others: https://dns.google/dns-query
```

You should configure dae as follows:

1. Complete `wan_interface` in "global" section to proxy requests of AdguardHome.

2. Insert following rule as the first line of "routing" section to avoid loops.

   ```python
   pname(AdGuardHome) && l4proto(udp) && dport(53) -> must_direct
   ```

   And make sure domain `dns.google` will be proxied in routing rules.

3. Add upstream and request to section "dns".

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

4. If you bind to LAN, make sure your DHCP server will distribute dae as the DNS server (DNS request should be forwarded by dae for domain based traffic split).

5. If there is still a DNS issue and there are no warn/error logs, you have to change your listening port of external DNS (here is AdGuardHome) from 53 to non-53 port. See [#31](https://github.com/daeuniverse/dae/issues/31#issuecomment-1467358364).

6. If you use PVE, refer to [#37](https://github.com/daeuniverse/dae/discussions/37).

## External DNS on another machine in LAN

If you set up a external DNS on another machine in LAN, you may want to let the DNS queries to dns.google proxied. For example, if you have following configuration in AdguardHome:

```
Listen on: 192.168.30.3:53 (mac address: 8c:16:45:36:1c:5a)

China mainland: udp://223.5.5.5:53
Others: https://dns.google/dns-query
```

You should configure dae as follows:

1. Fill in `lan_interface` in "global" section to proxy requests of AdguardHome.

2. Insert following rule as the first line of "routing" section to avoid loops.

   ```python
   sip(192.168.30.3) && l4proto(udp) && dport(53) -> must_direct
   # Or use MAC address if in the same link:
   # mac(8c:16:45:36:1c:5a) && l4proto(udp) && dport(53) -> must_direct
   ```
   
   And make sure domain `dns.google` will be proxied in routing rules.
   
3. Add upstream and request to section "dns".

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

4. If you bind to LAN, make sure your DHCP server will distribute dae as the DNS server (DNS request should be forwarded by dae for domain based traffic split).

5. If there is still a DNS issue and there are no warn/error logs, you have to change your listening port of external DNS (here is AdGuardHome) from 53 to non-53 port. See [#31](https://github.com/daeuniverse/dae/issues/31#issuecomment-1467358364).

6. If you use PVE, refer to [#37](https://github.com/daeuniverse/dae/discussions/37).
