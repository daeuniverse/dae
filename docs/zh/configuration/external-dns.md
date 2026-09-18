# 外部 DNS

本页说明如何让外部解析器（示例为 AdGuardHome）应答 dae 拦截到的全部 DNS 查询，同时让解析器自己的上游查询经 dae 及其代理发出。解析器可以运行在 dae 主机上，也可以运行在局域网内的另一台机器上。dae 如何拦截 DNS、嗅探到的域名如何反馈给路由，见 [DNS](dns.md) 和[工作原理](../how-it-works.md)。

## dae 主机上的外部 DNS

AdGuardHome 运行在 dae 主机上，中国大陆域名直接解析，其余域名经 `dns.google` 解析：

```
Listen on: the same machine with dae, port 53.

China mainland: udp://223.5.5.5:53
Others: https://dns.google/dns-query
```

按以下方式配置 dae：

1. 在 `global` 部分填写 `wan_interface`，让 AdGuardHome 自己的上游查询经 dae 离开主机，从而可以被代理。

2. 在 `routing` 部分的第一行插入以下规则。没有这条规则，dae 会拦截 AdGuardHome 发往 `223.5.5.5` 的明文 UDP 查询，再交回 AdGuardHome，形成环路：

   ```python
   pname(AdGuardHome) && l4proto(udp) && dport(53) -> must_direct
   ```

   保留一条让 `dns.google` 走代理的路由规则，DoH 上游才会被代理。

3. 在 `dns` 部分把 AdGuardHome 设为所有被拦截查询的上游：

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

4. 绑定 WAN 时，把 `/etc/resolv.conf` 指向公网解析器，例如 `nameserver 119.29.29.29`，不要指向本机的 AdGuardHome。发往 `127.0.0.1` 的查询停留在 loopback 接口，到不了 dae。发往公网地址的查询经网卡离开主机，由 dae 拦截后按 `dns` 部分交给 AdGuardHome，因此 dae 能看到应答。

   重启后，dnsmasq 等 DNS 服务通常会还原 `/etc/resolv.conf`。遇到此情况，卸载这些服务，或执行 `sudo chattr +i /etc/resolv.conf`。

5. 绑定 LAN 时，让 DHCP 服务器下发公网解析器作为 DNS 服务器，不要下发 dae 主机。局域网客户端发往 dae 主机 53 端口的 UDP 查询在路由之前就交给了 AdGuardHome，dae 看不到应答，`domain()` 规则也就不会匹配该客户端的流量。发往其他任何地址的查询都会被 dae 拦截，经 AdGuardHome 应答，dae 能看到应答。

6. 如果仍有 DNS 问题且没有 warn/error 日志，把 AdGuardHome 的监听端口从 53 改开。网卡无法关闭校验和验证时，另一个程序占用 53 端口会破坏拦截，见 [#31](https://github.com/daeuniverse/dae/issues/31#issuecomment-1467358364)。

7. 如果使用 PVE，参见 [#37](https://github.com/daeuniverse/dae/discussions/37)。

## 局域网内另一台机器上的外部 DNS

AdGuardHome 运行在局域网内的另一台机器上：

```
Listen on: 192.168.30.3:53 (mac address: 8c:16:45:36:1c:5a)

China mainland: udp://223.5.5.5:53
Others: https://dns.google/dns-query
```

按以下方式配置 dae：

1. 在 `global` 部分填写 `lan_interface`，让 AdGuardHome 自己的上游查询经过 dae，从而可以被代理。

2. 在 `routing` 部分的第一行插入以下规则，原因与本机部署相同：

   ```python
   sip(192.168.30.3) && l4proto(udp) && dport(53) -> must_direct
   # Or use MAC address if in the same link:
   # mac('8c:16:45:36:1c:5a') && l4proto(udp) && dport(53) -> must_direct
   ```

   保留一条让 `dns.google` 走代理的路由规则。

3. 在 `dns` 部分把 AdGuardHome 设为所有被拦截查询的上游：

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

4. 让 DHCP 服务器下发公网解析器作为 DNS 服务器，不要下发 AdGuardHome 所在的机器。直接发往 `192.168.30.3` 的查询通常在局域网内直达，不经过 dae，dae 看不到应答；发往其他任何地址的查询都会被 dae 拦截，经 AdGuardHome 应答，dae 能看到应答。

5. 如果仍有 DNS 问题且没有 warn/error 日志，把 AdGuardHome 的监听端口从 53 改开，见 [#31](https://github.com/daeuniverse/dae/issues/31#issuecomment-1467358364)。

6. 如果使用 PVE，参见 [#37](https://github.com/daeuniverse/dae/discussions/37)。
