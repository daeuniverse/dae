# 路由规则

## 示例

### 内置出站

```shell
### Built-in outbounds: block, direct, must_rules

# must_rules means no redirecting DNS traffic to dae and continue to matching.
# For single rule, the difference between "direct" and "must_direct" is that "direct" will hijack and process DNS request
# (for traffic split use), but "must_direct" will not. "must_direct" is useful when there are traffic loops of DNS requests.
# "must_direct" can also be written as "direct(must)".
# Similarly, "must_groupname" is also supported to NOT hijack and process DNS traffic, which equals to "groupname(must)".
```

### 默认出站

```shell
### fallback outbound
# If no rule matches, traffic will go through the outbound defined by fallback.
fallback: my_group
```

### 域名规则

```shell
### Domain rule
domain(suffix: v2raya.org) -> my_group  # equals to domain(v2raya.org) -> my_group 
domain(full: dns.google) -> my_group
domain(keyword: facebook) -> my_group
domain(regex: '\.goo.*\.com$') -> my_group
domain(geosite:category-ads) -> block
domain(geosite:cn)->direct
```

### 目标 IP

```shell
### Dest IP rule
dip(8.8.8.8) -> direct
dip(101.97.0.0/16) -> direct
dip(geoip:private) -> direct
```

### 来源 IP

```shell
### Source IP rule
sip(192.168.0.0/24) -> my_group
sip(192.168.50.0/24) -> direct
```

### 目标端口

```shell
### Dest port rule
dport(80) -> direct
dport(10080-30000) -> direct
```

### 来源端口

```shell
### Source port rule
sport(38563) -> direct
sport(10080-30000) -> direct
```

### 传输层协议

```shell
### Level 4 protocol rule:
l4proto(tcp) -> my_group
l4proto(udp) -> direct
```

### IP 版本

```shell
### IP version rule:
ipversion(4) -> block
ipversion(6) -> ipv6_group
```

### 来源 MAC

```shell
### Source MAC rule
mac('02:42:ac:11:00:02') -> direct
```

### 进程名称

```shell
### Process Name rule (only support localhost process when binding to WAN)
pname(curl) -> direct
```

### DSCP

```shell
### DSCP rule (match DSCP; is useful for BT bypass). See https://github.com/daeuniverse/dae/discussions/295
dscp(0x4) -> direct
```

### 多个域名

```shell
### Multiple domains rule
domain(keyword: google, suffix: www.twitter.com, suffix: v2raya.org) -> my_group
```

### 多个 IP 地址

```shell
### Multiple IP rule
dip(geoip:cn, geoip:private) -> direct
dip(9.9.9.9, 223.5.5.5) -> direct
sip(192.168.0.6, 192.168.0.10, 192.168.0.15) -> direct
```

### 与条件

```shell
### 'And' rule
dip(geoip:cn) && dport(80) -> direct
dip(8.8.8.8) && l4proto(tcp) && dport(1-1023, 8443) -> my_group
dip(1.1.1.1) && sip(10.0.0.1, 172.20.0.0/16) -> direct
```

### 非条件

```shell
### 'Not' rule
!domain(geosite:google-scholar,
        geosite:category-scholar-!cn,
        geosite:category-scholar-cn
    ) -> my_group
```

### 组合条件

```shell
### Little more complex rule
domain(geosite:geolocation-!cn) &&
    !domain(geosite:google-scholar,
            geosite:category-scholar-!cn,
            geosite:category-scholar-cn
        ) -> my_group
```

### 自定义 DAT 文件

```shell
### Customized DAT file
domain(ext:"yourdatfile.dat:yourtag")->direct
dip(ext:"yourdatfile.dat:yourtag")->direct
```

### fwmark

```shell
### Set fwmark
# Mark is useful when you want to redirect traffic to specific interface (such as wireguard) or for other advanced uses.

# An example of redirecting Disney traffic to wg0 is given here.
# You need set ip rule and ip table like this:
# 1. Set all traffic with mark 0x800/0x800 to use route table 1145:
# >> ip rule add fwmark 0x800/0x800 table 1145
# >> ip -6 rule add fwmark 0x800/0x800 table 1145
# 2. Set default route of route table 1145:
# >> ip route add default dev wg0 scope global table 1145
# >> ip -6 route add default dev wg0 scope global table 1145
# Notice that interface wg0, mark 0x800, table 1145 can be set by preferences, but cannot conflict.
# Notice also that dae marks its own egress traffic with an internal mark (0x100) unless
# so_mark_from_dae sets another one: a rule written for *unmarked* traffic does not match
# dae's own egress, and a rule that matches 0x100 affects dae's own traffic as well.
# 3. Set routing rules in dae config file.
domain(geosite:disney) -> direct(mark: 0x800)
```

### Must 规则

```shell
### Must rules
# For following rules, DNS requests will be forcibly redirected to dae except from mosdns.
# Different from must_direct/must_my_group, traffic from mosdns will continue to match other rules.
pname(mosdns) -> must_rules
ip(geoip:cn) -> direct
domain(geosite:cn) -> direct
fallback: my_group
```

## 按设备限定的域名白名单（自动 sniff-punt）

```shell
mac('aa:bb:cc:dd:ee:ff') && domain(geosite:docker, suffix:quay.io, geosite:github) -> my_group
mac('aa:bb:cc:dd:ee:ff') -> direct
```

内核匹配 `domain` 条件时，用连接的目标 IP 查询 `domain_routing_map`。键不含来源 IP 或 MAC。值是所有经 dae 转发、且解析到该 IP 的 DNS 应答的域名位图按位或的结果，在这些 DNS 缓存条目存活期间一直有效。因此，只要另一个 dae 客户端或 dae 主机曾通过 dae 解析过目标 IP，使用加密 DNS（DoH/DoT）的设备仍能命中白名单。如果没有任何经 dae 转发的应答覆盖该目标 IP，连接就不带域名信息，会落到回退规则。

dae 会识别同时满足以下条件的规则组合：

- 使用单主机 `mac`/`sip` 选择器。
- 包含正向 `domain` 条件。
- 后面有一条仅含该选择器的 `direct`/`block` 回退规则。

dae 会在回退规则前自动插入一条仅在内核空间生效的 sniff-punt 规则。该规则将缺少域名信息的连接送到用户空间，嗅探 TLS SNI、HTTP host 或 QUIC，再用嗅探到的域名重新匹配同一组规则。

这种恢复是有条件的，因为 dae 只嗅探一部分送到用户空间的连接。dae 从不嗅探目标端口为 20、21、22、25、53、119、123、161、3306、5432、6379、9200、27017 和 11211 的 TCP 连接，这份列表是硬编码的。TCP 连接的前几个字节不是 TLS 握手或 HTTP 请求时，dae 也会跳过嗅探。相同的目标、进程名、MAC 和 DSCP 已连续 3 次嗅探失败时，dae 同样跳过，并对该组合暂停嗅探 10 分钟。

dae 只在来源端口或目标端口为 443 或 8443 且数据包是 QUIC Initial 时才嗅探 UDP。对被跳过的连接和嗅探不到域名的连接，dae 会不带域名重新路由。白名单规则因此无法命中，连接会落到回退规则。

该设备未命中白名单的流量仍会落到回退规则，并经用户空间转发。

使用此功能需要启用嗅探（`sniffing_timeout > 0`、`dial_mode != ip`）。可通过 `auto_sniff_punt: false` 关闭此功能。

## 参数名与取反规则

以下接受无名参数值的函数会拒绝不支持的参数名：`pname`、`port`/`dport`、`sport`、`dscp`、`ip`/`dip`、`sip`、`ipversion`、`l4proto`、`mac`、`qtype`，以及响应路由中的 `upstream`。

语法允许在所有函数调用中使用 `key: value`。这些函数的解析器以前会忽略未知参数名，因此 `port(bogus_param: 443)` 会在没有提示的情况下生成与 `port(443)` 相同的 match set。`pname(bogus_param: 1)` 则会匹配名为 `1` 的进程。

现在，这类规则会报错 `unsupported parameter key "bogus_param"`，并指出接受的写法。函数原本支持的值前缀 `geoip:`、`geosite:` 和 `ext:` 不受影响，例如 `dip(geoip:cn)` 和 `dip(ext:"file.dat:tag")`。不带参数名的 `pname(NetworkManager)` 和 `port(443)` 也不受影响。

如果配置在上述函数中使用了误写的参数名，dae 将无法启动，直到移除该参数名。升级前请检查路由部分。

优化器不再合并出站相同、且仅含一个函数的取反规则。规则按顺序匹配，因此以下两条独立规则会将未命中 `a` **或**未命中 `b` 的流量发送到 `my_group`：

```shell
!domain(geosite:a) -> my_group
!domain(geosite:b) -> my_group
```

合并后的 `!domain(geosite:a, geosite:b)` 对整个集合取反，仅匹配**同时未命中** `a` 和 `b` 的流量，范围更窄。dae 现在保留原来的两条规则，因此依赖旧合并行为的配置会匹配比以前更多的流量。
