# 外部 DNS

> **注意**
> 让 DNS 请求经 dae 转发，才能完整地按域名分流。内核侧的 `domain()` 规则只有在 dae 看到过 DNS 应答后才会命中。在默认的 `dial_mode: domain` 下，dae 还会对内核送往代理出站的连接，用嗅探到的域名重新匹配路由规则。前提是 DNS 应答经过了 dae，或经 `bootstrap_resolver` 的后台探测（默认 119.29.29.29:53 和 223.5.5.5:53）确认了该域名。首次连接未知域名时仍沿用按 IP 的判定；内核送往 `direct` 或 `block` 的流量不会重新匹配。`domain++` 不做上述检查，对每个嗅探到域名的连接都重新匹配；`domain+` 从不重新匹配。

使用 AdGuardHome 等外部 DNS 时，请按部署位置配置 dae。

## 本机上的外部 DNS

在本机部署外部 DNS 时，如需代理发往 `dns.google` 的 DNS 查询，可按以下示例配置。假设 AdGuardHome 的配置如下：

```
Listen on: the same machine with dae, port 53.

China mainland: udp://223.5.5.5:53
Others: https://dns.google/dns-query
```

应按以下方式配置 dae：

1. 在 `global` 部分填写 `wan_interface`，以代理 AdGuardHome 的请求。

2. 将以下规则插入 `routing` 部分的第一行，以避免环路。

   ```python
   pname(AdGuardHome) && l4proto(udp) && dport(53) -> must_direct
   ```

   确保路由规则会代理域名 `dns.google`。

3. 在 `dns` 部分添加 `upstream` 和 `request`。

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

4. 绑定 WAN 时，确保 `/etc/resolv.conf` 不直接使用本机外部 DNS。例如，可设置为 `nameserver 119.29.29.29`；数据包经由网卡发送时，DNS 流量会被 dae 劫持。

   重启后，dnsmasq 等 DNS 服务通常会还原 `/etc/resolv.conf`。遇到此情况，建议卸载这些服务，或执行 `sudo chattr +i /etc/resolv.conf` 将文件设为不可修改。

5. 如果绑定到 LAN，请确保 DHCP 服务器将 dae 作为 DNS 服务器下发。内核侧的 `domain()` 规则只有在 DNS 请求经过 dae 时才会命中。

6. 如果仍有 DNS 问题且没有 warn/error 日志，必须将外部 DNS（此处为 AdGuardHome）的监听端口从 53 改为非 53 端口。参见 [#31](https://github.com/daeuniverse/dae/issues/31#issuecomment-1467358364)。

7. 如果使用 PVE，参见 [#37](https://github.com/daeuniverse/dae/discussions/37)。

## LAN 中另一台机器上的外部 DNS

在 LAN 中另一台机器上部署外部 DNS 时，如需代理发往 `dns.google` 的 DNS 查询，可按以下示例配置。假设 AdGuardHome 的配置如下：

```
Listen on: 192.168.30.3:53 (mac address: 8c:16:45:36:1c:5a)

China mainland: udp://223.5.5.5:53
Others: https://dns.google/dns-query
```

应按以下方式配置 dae：

1. 在 `global.lan_interface` 中填写 AdGuardHome 所在 LAN 的接口，以代理其请求。

2. 为避免环路，将以下规则放在 `routing` 部分的第一行。

   ```python
   sip(192.168.30.3) && l4proto(udp) && dport(53) -> must_direct
   # Or use MAC address if in the same link:
   # mac('8c:16:45:36:1c:5a') && l4proto(udp) && dport(53) -> must_direct
   ```

   路由规则还需代理域名 `dns.google`。

3. 将以下 `upstream` 和 `request` 配置添加到 `dns` 部分。

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

4. 如果绑定到 LAN，请确保 DHCP 服务器将 dae 作为 DNS 服务器下发。内核侧的 `domain()` 规则只有在 DNS 请求经过 dae 时才会命中。

5. 如果仍有 DNS 问题且没有 warn/error 日志，必须将外部 DNS（此处为 AdGuardHome）的监听端口从 53 改为非 53 端口。参见 [#31](https://github.com/daeuniverse/dae/issues/31#issuecomment-1467358364)。

6. 如果使用 PVE，参见 [#37](https://github.com/daeuniverse/dae/discussions/37)。
