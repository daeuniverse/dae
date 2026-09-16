# 路由

## 例子

```shell
### 内置出站：block, direct, must_rules

# must_rules 表示不将 DNS 流量重定向至 dae 并继续匹配。
# 对于单条规则，"direct"和"must_direct"的区别在于"direct"会劫持并处理 DNS 请求（用于流量分割使用），而"must_direct"不会。
# 当存在 DNS 请求的回环时，"must_direct"很有用。
# "must_direct" 也可以写作 "direct(must)"。
# 同样，"must_groupname"也支持不劫持、处理 DNS 流量，相当于"groupname(must)"。

### fallback 出站
# 如果没有规则匹配，流量将通过 fallback 出站。
fallback: my_group

### 域名规则
domain(suffix: v2raya.org) -> my_group # 相当于 domain(v2raya.org) -> my_group 
domain(full: dns.google) -> my_group
domain(keyword: facebook) -> my_group
domain(regex: '\.goo.*\.com$') -> my_group
domain(geosite:category-ads) -> block
domain(geosite:cn)->direct

### 目标 IP 规则
dip(8.8.8.8) -> direct
dip(101.97.0.0/16) -> direct
dip(geoip:private) -> direct

### 源 IP 规则
sip(192.168.0.0/24) -> my_group
sip(192.168.50.0/24) -> direct

### 目标端口规则
dport(80) -> direct
dport(10080-30000) -> direct

### 源端口规则
sport(38563) -> direct
sport(10080-30000) -> direct

### 四层协议规则：
l4proto(tcp) -> my_group
l4proto(udp) -> direct

### IP 版本规则：
ipversion(4) -> block
ipversion(6) -> ipv6_group

### 源 MAC 地址规则
mac('02:42:ac:11:00:02') -> direct

### 进程名称规则（绑定 WAN 时仅支持本机进程）
pname(curl) -> direct

### DSCP 规则（匹配 DSCP，可用于绕过 BT），见 https://github.com/daeuniverse/dae/discussions/295
dscp(0x4) -> direct

### 多个域名规则
domain(keyword: google, suffix: www.twitter.com, suffix: v2raya.org) -> my_group
### 多个 IP 规则
dip(geoip:cn, geoip:private) -> direct
dip(9.9.9.9, 223.5.5.5) -> direct
sip(192.168.0.6, 192.168.0.10, 192.168.0.15) -> direct

### "并"规则
dip(geoip:cn) && dport(80) -> direct
dip(8.8.8.8) && l4proto(tcp) && dport(1-1023, 8443) -> my_group
dip(1.1.1.1) && sip(10.0.0.1, 172.20.0.0/16) -> direct

### "非"规则
!domain(geosite:google-scholar,
        geosite:category-scholar-!cn,
        geosite:category-scholar-cn
    ) -> my_group

### 更复杂一点的规则
domain(geosite:geolocation-!cn) &&
    !domain(geosite:google-scholar,
            geosite:category-scholar-!cn,
            geosite:category-scholar-cn
        ) -> my_group

### 个性化 DAT 文件
domain(ext:"yourdatfile.dat:yourtag")->direct
dip(ext:"yourdatfile.dat:yourtag")->direct

### 设置防火墙标记
# 当您想要将流量重定向到特定接口（例如 wireguard）或用于其他高级用途时，标记非常有用。
# 这里给出了将 Disney 流量重定向到 wg0 的示例。
# 您需要像这样设置 ip 规则和 ip 路由表：
# 1. 将所有标记为 0x800/0x800 的流量设置为使用路由表 1145：
# >> ip rule add fwmark 0x800/0x800 table 1145
# >> ip -6 rule add fwmark 0x800/0x800 table 1145
# 2. 设置路由表 1145 的默认路由：
# >> ip route add default dev wg0 scope global table 1145
# >> ip -6 route add default dev wg0 scope global table 1145
# 注意：接口 wg0，标记 0x800，表 1145 可以通过首选项设置，但不能冲突。
# 另请注意：dae 自身的外发流量带有内部标记（未设置 so_mark_from_dae 时为 0x100），
# 因此针对「无标记」流量的规则不会匹配 dae 自身的外发流量，而匹配 0x100 的规则会同时作用于 dae 自身的流量。
# 3. 在 dae 配置文件中设置路由规则。
domain(geosite:disney) -> direct(mark: 0x800)

### Must 规则
# 使用下面给出的规则，DNS 请求将被强制重定向到 dae，除了来自 mosdns 的请求。
# 与 must_direct/must_my_group 不同，来自 mosdns 的流量将继续匹配其他规则。
pname(mosdns) -> must_rules
ip(geoip:cn) -> direct
domain(geosite:cn) -> direct
fallback: my_group
```

## 设备级域名白名单（自动 sniff-punt）

```shell
mac('aa:bb:cc:dd:ee:ff') && domain(geosite:docker, suffix:quay.io, geosite:github) -> my_group
mac('aa:bb:cc:dd:ee:ff') -> direct
```

域名条件依赖「该设备的 DNS 经过 dae」才存在的信息。如果该设备使用加密 DNS
（DoH/DoT），白名单会静默失效，它的全部流量都会落到 fallback。dae 能识别这种形态
（单主机 `mac`/`sip` 选择器 + 正向 `domain` 条件 + 之后仅选择器的 `direct`/`block`
fallback），并自动在 fallback 之前插入一条仅在内核态生效的 sniff-punt 规则：缺少域名
信息的连接被送往用户态嗅探（TLS SNI / HTTP host / QUIC），再用嗅探到的域名在同一条
规则集上重新匹配。该设备未被白名单命中的流量仍落到 fallback，经用户态转发。使用前提是
嗅探已启用（`sniffing_timeout > 0`、`dial_mode != ip`）；用 `auto_sniff_punt: false` 关闭。
