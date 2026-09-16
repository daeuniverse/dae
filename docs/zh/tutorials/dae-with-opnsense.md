# dae 与 OPNsense: 最佳实践

本教程展示了如何以旁挂的方式将 dae 和 OPNsense 一起使用。dae 安装在另一个 Linux 系统中，和 OPNsense 通过以太网连接（物理连接、Linux 网桥或 SR-IOV）。

## 接口

你应该为 dae 和 OPN 之间的接口分配和 OPN 的 LAN 不同网段的地址。如果把这个接口称为 wan_proxy，配置如下：

```
OPN LAN: 192.168.1.1/24
OPN wan_proxy: 192.168.2.2 网关 自动检测
dae enp1s0：192.168.2.1 网关 192.168.2.2
```

## 分流

1.配置 geoip 列表

   > 在`防火墙：别名：GeoIP设置`中添加，参考[OPN 文档](https://docs.opnsense.org/manual/how-tos/maxmind_geo_ip.html)。

2.配置 geoip 别名

   > 在`防火墙：别名：别名`处添加别名 proxyip，选择 GeoIP 类型，在显示的区域 Asia 中选择 China（或你所在的其他国家）。

3.添加额外 IP 地址列表（可选）

   > 在`防火墙：别名：别名`处添加别名 proxyip_ex，选择 URL Table 类型，可添加其他人维护的 IP 列表链接，文件内容为每行一个 CIDR 表示的 IP 地址。

4.配置保留地址别名

   > 在`防火墙：别名：别名`处添加别名\_\_private_network，选择 Network 类型，添加所有保留地址（或仅添加自己网络中使用到的保留地址），参考[保留 IP 地址](https://www.wikiwand.com/zh-hant/保留IP地址)。

5.聚合以上别名

   > 在`防火墙：别名：别名`处添加别名 proxyroute，选择 Network group 类型，内容选择 proxyip、proxyip_ex（如果有）、\_\_private_network 以及系统内置的\_\_lo0_network 别名，对其进行聚合。

6.添加网关

   > 在`系统：网关：单个`处添加网关 proxy，接口选择和 dae 之间的接口 wan_proxy，IP 为 dae 的 IP，按上文接口示例这里填写 192.168.2.1，优先级须低于默认网关，如默认网关设为 254，这里设为 255。

7.分流规则

   > 在`防火墙: 规则: 浮动`处添加规则，进行如下配置：

   | 项目 | 配置 |
   | - | - |
   | 操作 | 通过 |
   | 快速 | √ |
   | 接口 | LAN |
   | 方向 | in |
   | TCP/IP版本 | IPv4 |
   | 协议 | TCP/UDP |
   | 目标/反转 | √ |
   | 目标 | proxyroute |
   | 网关 | proxy |

   > 此外可以通过源、源/反转来排除局域网设备，使其流量不会被分流到 dae。

8.允许 dae 流量进入 OPN

   > 在`防火墙：规则：wan_proxy`新建规则，全部保持默认保存即可。

9.OPN 自身代理 (可选)

   > 如果需要让 OPN 自己的某些流量走代理，如使用 Google Drive 备份配置，建议在`系统: 路由: 配置`中添加静态路由规则进行配置，将需要走代理的 IP 段，网关设为 proxy。不建议在浮动规则中对 WAN 流量进行处理，可能会造成回环。

## dae 相关配置

本节不涉及 dae 的配置文件内容，只给出如何配置使 DNS 请求经过 dae，以及常见的代理正常直连不通问题的解决方法。以下提到的 dae 的`domain`、`ip`模式以及如何配置 dae 的`dns`和`routing`规则，请查阅 dae 文档。

使用 dae 进行透明代理，要使基于域名的分流规则正常工作，`domain`和`domain+`模式下需要 DNS 请求经过 dae（注意不是将 DNS 服务器设为 dae 地址，dae 不监听 53 端口）。若 DNS 请求不经过 dae，需要使用 dae 的`domain++`模式（根据 sniff 到的域名再匹配一次分流规则，性能不如`domain`模式）。如使用 domain++ 模式，或不需要根据域名分流而使用`ip`模式，以下配置可忽略。

1.DNS 转发配置
   > 在`服务: Unbound DNS: 查询转发`中设置，将 DNS 请求转发到指定服务器，如配置为 OpenDNS 的 208.67.222.222。下面步骤需要设置静态路由规则，将该地址网关设为 dae，因此不要使用你的上游下发的 DNS，以便在排查 DNS 问题时，可以正常使用 dig 或 nslookup 向上游下发的 DNS 服务器查询进行测试。

2.静态路由配置
   > 在`系统: 路由: 配置`中添加静态路由规则，网络设为 208.67.222.222/32，网关设置为 proxy。

经过如上配置可以使 DNS 请求经过 dae，并被 dae 劫持处理，这里设置的 DNS 服务器并不是最终查询的服务器，DNS 查询的目标服务器会被 dae 根据 dae 配置中的 dns 规则改写，然后发送 DNS 查询请求。

需要注意的是 Unbound 会在转发客户端发出的 DNS 请求时，追加 EDNS 相关参数，这样可能会从上游服务器取得长度超大（偶见大于 2000）的 DNS 响应，从而导致 dae 处理 udp DNS 的缓冲区溢出（出于性能考虑，dae 没有使用更大的缓冲区，tcp 的 DNS 不会溢出），最终表现是客户端无法拿到 DNS 响应，甚至导致 dae 功能崩溃。要解决这个问题，可以改用 Dnsmasq 或在`服务：Unbound DNS：常规`中关闭 EDNSSEC 支持并写入如下 Unbound 配置，该配置可以有效减小返回的 DNS 响应大小：

``` yaml
# 存为 /usr/local/etc/unbound.opnsense.d/disableedns.conf
server:
    disable-edns-do: yes 
```

此外，由于 dae 不会进行 snat，如果出现代理正常直连不通[这里指的是 dae `routing` 中的 direct，而不是 OPN 没有分流给 dae 直接出 wan 口的流量。如根据上节配置的分流规则，OPN 会将 steam 的流量分流经过 dae，dae 在 `routing` 配置了 domain(geosite:steam@cn) -> direct，steam 无法正常登录或下载]，在安装 dae 的系统中配置 nat 即可。

## 性能优化

将 OPN 和 dae 之间的 MTU 值从默认的 1500 改为 9000(需要修改两者接口及中间链路)，可以获得更低负载。
