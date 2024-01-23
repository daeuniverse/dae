# dae与OPNsense: 最佳实践

本教程展示了如何以旁挂的方式将dae和OPNsense一起使用。dae安装在另一个Linux系统中，和OPNsense通过以太网连接（物理连接、Linux网桥或SR-IOV）。

## 接口

你应该为dae和OPN之间的接口分配和OPN的LAN不同网段的地址。如果把这个接口称为wan_proxy，配置如下：

```
OPN LAN: 192.168.1.1/24
OPN wan_proxy: 192.168.2.2 网关 自动检测
dae enp1s0：192.168.2.1 网关 192.168.2.2
```

## 分流

1.配置geoip列表

   > 在`防火墙：别名：GeoIP设置`中添加，参考[OPN文档](https://docs.opnsense.org/manual/how-tos/maxmind_geo_ip.html)。

2.配置geoip别名

   > 在`防火墙：别名：别名`处添加别名proxyip，选择GeoIP类型，在显示的区域Asia中选择China（或你所在的其他国家）。

3.添加额外IP地址列表（可选）

   > 在`防火墙：别名：别名`处添加别名proxyip_ex，选择URL Table类型，可添加其他人维护的IP列表链接，文件内容为每行一个CIDR表示的IP地址。

4.配置保留地址别名

   > 在`防火墙：别名：别名`处添加别名\_\_private_network，选择Network类型，添加所有保留地址（或仅添加自己网络中使用到的保留地址），参考[保留IP地址](ttps://www.wikiwand.com/zh-hant/保留IP地址)。

5.聚合以上别名

   > 在`防火墙：别名：别名`处添加别名proxyroute，选择Network group类型，内容选择proxyip、proxyip_ex（如果有）、\_\_private_network以及系统内置的\_\_lo0_network别名，对其进行聚合。

6.添加网关

   > 在`系统：网关：单个`处添加网关proxy，接口选择和dae之间的接口wan_proxy，IP为dae的IP，按上文接口示例这里填写192.168.2.1，优先级须低于默认网关，如默认网关设为254，这里设为255。

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
   | 网关 | 启用 |

   > 此外可以通过源、源/反转来排除局域网设备，使其流量不会被分流到dae。

8.允许dae流量进入OPN

   > 在`防火墙：规则：wan_proxy`新建规则，全部保持默认保存即可。

9.OPN自身代理(可选)

   > 如果需要让OPN自己的某些流量走代理，如使用Google Drive备份配置，建议在`系统: 路由: 配置`中添加静态路由规则进行配置，将需要走代理的IP段，网关设为proxy。不建议在浮动规则中对WAN流量进行处理，可能会造成回环。

## dae相关配置

本节不涉及dae的配置文件内容，只给出如何配置使DNS请求经过dae，以及常见的代理正常直连不通问题的解决方法。以下提到的dae的`domain`、`ip`模式以及如何配置dae的`dns`和`routing`规则，请查阅dae文档。

使用dae进行透明代理，要使基于域名的分流规则正常工作，`domain`和`domain+`模式下需要DNS请求经过dae（注意不是将DNS服务器设为dae地址，dae不监听53端口）。若DNS请求不经过dae，需要使用dae的`domain++`模式（根据sniff到的域名再匹配一次分流规则，性能不如`domain`模式）。如使用domain++模式，或不需要根据域名分流而使用`ip`模式，以下配置可忽略。

1.DNS转发配置
   > 在`服务: Unbound DNS: 查询转发`中设置，将DNS请求转发到指定服务器，如配置为OpenDNS的208.67.222.222。下面步骤需要设置静态路由规则，将该地址网关设为dae，因此不要使用你的上游下发的DNS，以便在排查DNS问题时，可以正常使用dig或nslookup向上游下发的DNS服务器查询进行测试。

2.静态路由配置
   > 在`系统: 路由: 配置`中添加静态路由规则，网络设为208.67.222.222/32，网关设置为proxy。

经过如上配置可以使DNS请求经过dae，并被dae劫持处理，这里设置的DNS服务器并不是最终查询的服务器，DNS查询的目标服务器会被dae根据dae配置中的dns规则改写，然后发送DNS查询请求。

需要注意的是Unbound会在转发客户端发出的DNS请求时，追加EDNS相关参数，这样可能会从上游服务器取得长度超大（偶见大于2000）的DNS响应，从而导致dae处理udp DNS的缓冲区溢出（处于性能考虑，dae没有使用更大的缓冲区，tcp的DNS不会溢出），最终表现是客户端无法拿到DNS响应，甚至导致dae功能崩溃。要解决这个问题，可以改用Dnsmasq或在`服务：Unbound DNS：常规`中关闭EDNSSEC支持并写入如下Unbound配置，该配置可以有效减小返回的DNS响应大小：

``` yaml
# 存为 /usr/local/etc/unbound.opnsense.d/disableedns.conf
server:
    disable-edns-do: yes 
```

此外，由于dae不会进行snat，如果出现代理正常直连不通[这里指的是dae `routing`中的direct，而不是OPN没有分流给dae直接出wan口的流量。如根据上节配置的分流规则，OPN会将steam的流量分流经过dae，dae在`routing`配置了domain(geosite:steam@cn) -> direct，steam无法正常登录或下载]，在安装dae的系统中配置nat即可。

## 性能优化

将OPN和dae之间的MTU值从默认的1500改为9000(需要修改两者接口及中间链路)，可以获得更低负载。
