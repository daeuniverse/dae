# OPNsense

dae 可在另一台 Linux 系统上以旁路方式配合 OPNsense 使用。两者通过以太网相连，可采用物理连接、Linux 网桥或 SR-IOV。

## 接口

dae 与 OPN 之间的接口地址应与 OPN LAN 位于不同子网。以下将该接口命名为 `wan_proxy`：

```
OPN LAN: 192.168.1.1/24
OPN wan_proxy: 192.168.2.2 Gateway Auto Detect
dae enp1s0: 192.168.2.1 Gateway 192.168.2.2
```

## 流量分流

1. 配置 GeoIP 列表

   > 在 `Firewall: Aliases: GeoIP Settings` 中添加；请参阅 [OPN 文档](https://docs.opnsense.org/manual/how-tos/maxmind_geo_ip.html)。

2. 配置 GeoIP 别名

   在 `Firewall: Aliases: Aliases` 中添加名为 `proxyip` 的别名，类型选择 GeoIP。在 Asia 区域选择 China，或选择自己的国家。

3. 添加额外 IP 地址列表（可选）

   在 `Firewall: Aliases: Aliases` 中添加名为 `proxyip_ex` 的别名，类型选择 URL Table。可添加他人维护的 IP 列表链接。列表文件应每行包含一个以 CIDR 表示的 IP 地址。

4. 配置保留地址别名

   在 `Firewall: Aliases: Aliases` 中添加名为 `__private_network` 的别名，类型选择 Network。添加所有保留地址，或仅添加当前网络使用的保留地址。参阅[保留 IP 地址](https://www.wikiwand.com/zh-hant/保留IP地址)。

5. 聚合上述别名

   在 `Firewall: Aliases: Aliases` 中添加名为 `proxyroute` 的别名，类型选择 Network group。将以下别名加入该组：

   - `proxyip`
   - `proxyip_ex`（如有）
   - `__private_network`
   - 系统内置的 `__lo0_network`

6. 添加网关

   在 `System: Gateways: Single` 中添加名为 `proxy` 的网关：

   | 项目 | 配置 |
   | --- | --- |
   | 接口 | 与 dae 相连的 `wan_proxy` |
   | IP 地址 | dae 的 IP，按前面的示例为 `192.168.2.1` |
   | 优先级 | 低于默认网关；例如默认网关为 `254` 时，此处设为 `255` |

7. 流量分流规则

   > 在 `Firewall: Rules: Floating` 中添加规则，配置如下：

   | 项目 | 配置 |
   | - | - |
   | 操作 | Pass |
   | Quick | √ |
   | 接口 | LAN |
   | 方向 | in |
   | TCP/IP 版本 | IPv4 |
   | 协议 | TCP/UDP |
   | 目的地/反转 | √ |
   | 目的地 | proxyroute |
   | 网关 | proxy |

   > 此外，可通过 Source/Invert 排除 LAN 设备，使其流量不会经过 dae。

8. 允许 dae 流量进入 OPN

   > 在 `Firewall: Rules: wan_proxy` 中新建规则，保留所有默认值并保存。

9. OPN 自身的代理（可选）

   如需代理 OPN 自身的部分流量，例如将配置备份到 Google Drive，建议在 `System: Routes: Configuration` 中添加静态路由规则。将需代理 IP 段的网关设为 `proxy`。不建议在浮动规则中处理 WAN 流量，否则可能形成环路。

## dae 相关配置

本节说明如何让 DNS 请求经过 dae，以及如何排查代理正常但直连失败的问题，不涉及 dae 配置文件的内容。`domain`、`ip` 模式，以及 `dns`、`routing` 规则的配置方法，请参阅 dae 文档。

| 模式 | DNS 与域名分流要求 |
| --- | --- |
| `domain` | DNS 请求必须经过 dae，内核侧的 `domain()` 规则才会命中。DNS 请求无法经过 dae 时，对内核已发往代理出站的连接，dae 仍会用嗅探到的域名重新匹配分流规则，但要先确认该域名。确认依据是 dae 的 DNS 缓存，或经 `bootstrap_resolver`（默认 `119.29.29.29:53` 和 `223.5.5.5:53`）的后台探测。到未知域名的第一条连接沿用内核按 IP 的判定，dae 只为后续连接重新匹配分流规则 |
| `domain+` | DNS 请求必须经过 dae，内核侧的 `domain()` 规则才会命中；从不重新匹配分流规则 |
| `domain++` | DNS 请求不经过 dae 时使用；用每个嗅探到的域名重新匹配分流规则，不做确认，性能不如 `domain` 模式 |
| `ip` | 不需要按域名分流时使用 |

dae 默认不开启 DNS 监听器，所以把 DNS 服务器设为 dae 地址不起作用。要让 dae 充当 DNS 服务器，设置 `dns { bind: '192.168.2.1:53' }`。只写 `ip:port` 仅监听 UDP；写 `tcp+udp://192.168.2.1:53` 则同时监听 TCP 和 UDP。该监听器收到的查询使用同一套 `dns` 规则和缓存。

任何模式都不会为内核已发往 `direct` 或 `block` 的连接重新匹配分流规则。使用 `domain++`，或无需按域名分流而使用 `ip` 时，可忽略以下配置。

1. DNS 转发配置

   在 `Services: Unbound DNS: Query Forwarding` 中，将 DNS 请求转发至指定服务器，例如 OpenDNS 的 `208.67.222.222`。

   下一步会将该地址的网关设为 dae，因此不要选择上游下发的 DNS。这样排查 DNS 问题时，仍可用 `dig` 或 `nslookup` 直接查询上游下发的 DNS 服务器进行测试。

2. 静态路由配置
   > 在 `System: Routes: Configuration` 添加静态路由规则，将网络设为 208.67.222.222/32，并将网关设为 proxy。

完成配置后，DNS 请求会经过 dae，由 dae 劫持处理。此处设置的 DNS 服务器不是最终查询服务器。dae 会按配置中的 `dns` 规则重写目标服务器，再发送查询。

Unbound 转发客户端 DNS 请求时会附加 EDNS 参数。dae 用 65536 字节的缓冲区读取上游 UDP 响应，所以较大的 EDNS 响应能完整收到。对 `udp://` 和 `tcp+udp://` 上游，收到 TC=1 的响应时，dae 会改经 TCP 重试该查询。返回给客户端的响应超过客户端在 EDNS0 中声明的 UDP 大小（查询不带 EDNS0 时为 512 字节）时，dae 会截断该响应并设置 TC=1，让客户端改经 TCP 重试。

因此不必改用 Dnsmasq，也不必在 Unbound 中禁用 EDNS。如仍要禁用，在 `Services: Unbound DNS: General` 中禁用 DNSSEC 支持，并写入以下 Unbound 配置：

``` yaml
# saved as /usr/local/etc/unbound.opnsense.d/disableedns.conf
server:
    disable-edns-do: yes 
```

dae 不执行 SNAT。如果代理正常但直连失败，请在安装 dae 的系统中配置 NAT。

这里的直连指 dae `routing` 中的 `direct`，不是 OPN 未分流到 dae、直接从 WAN 端口发出的流量。例如，按上一节的规则，OPN 会将 Steam 流量分流到 dae。即使 dae 已配置 `domain(geosite:steam@cn) -> direct`，Steam 仍可能无法正常登录或下载。

## 性能优化

将 OPN 与 dae 之间的 MTU 值从默认 1500 改为 9000（需修改两个接口和中间链路），可实现更低负载。
