# DNS

dae 会拦截所有经它路由或从本机发出、发往 53 端口的 UDP 和 TCP 流量，并嗅探 DNS。只有命中 `must_direct` 的流量不经过 dae；仅写 `direct` 仍会交给 DNS 模块处理。两种情况不会进入 DNS 模块。局域网客户端发往 dae 主机自身 socket（例如本机监听 53 端口的 dnsmasq）的 UDP 查询，在路由之前就交给该 socket。经 loopback 接口的查询不会经过 dae 的任何 hook。局域网客户端发往该本机 socket 的 TCP 查询仍会经过路由。

dae 不重组 IP 分片：只处理数据报的第一个分片，后续分片原样放行，因此被分片的 UDP DNS 报文无法被正确拦截。若为局域网客户端应答的解析器自己的上游查询走了 `must_direct` 规则，dae 看不到这些应答，也就学不到返回 IP 对应的域名，`domain()` 规则不会匹配客户端的流量。

## URI 格式

### DoH3

```
h3://<host>:<port>/<path>
http3://<host>:<port>/<path>

default port: 443
default path: /dns-query
```

### DoH

```
https://<host>:<port>/<path>

default port: 443
default path: /dns-query
```

### DoT

```
tls://<host>:<port>

default port: 853
```

### DoQ

```
quic://<host>:<port>

default port: 853
```

### UDP

```
udp://<host>:<port>

default port: 53
```

### TCP

```
tcp://<host>:<port>

default port: 53
```

### TCP 和 UDP

```
tcp+udp://<host>:<port>

default port: 53
```

对于 dae 代替客户端转发的查询，收到截断的响应（`TC=1`，RFC 1035 §4.2.1）时，dae 会按 RFC 7766 §5 的要求通过 TCP 重试。`udp://` 上游只在响应被截断后重试；`tcp+udp://` 上游在任何 UDP 失败后都会重试。由 `sub()`、`node()` 和 `subnode()` 选中的 dae 自身查询在 `udp://` 上游没有这种重试。响应被截断时查询直接失败，错误为 `internal dns response truncated`。只有 `tcp+udp://` 上游会通过 TCP 重试这些查询，因此预期响应较大时，这些规则应指向 `tcp+udp://` 或 `tcp://` 上游。

内置目标 `asis` 沿用客户端所用的地址和端口，但不沿用客户端的传输方式：dae 总是通过 UDP 查询该服务器，即使客户端是通过 TCP 发起查询。`asis` 不会通过 TCP 重试。该服务器回复 `TC=1` 时，dae 丢弃服务器的响应。dae 改为根据客户端的查询构造一条消息回复客户端：ID 和 Question 段与查询相同，`NOERROR`、`RA=1`、`TC=1`，Answer 段为空。之后由客户端决定是否通过 TCP 重试。其他协议仍使用各自指定的传输方式。

## 示例

```shell
dns {
    # For example, if ipversion_prefer is 4 and dae already knows the domain has type A records, dae returns an empty
    # answer to type AAAA queries; otherwise dae returns the AAAA answer unchanged.
    ipversion_prefer: 4

    # Give a fixed ttl for domains. Zero makes the cached answer expire immediately; with optimistic_cache (default true)
    # dae may still serve it as a stale answer while refreshing.
    fixed_domain_ttl {
        ddns.example.org: 10
        test.example.org: 3600
    }

    # Bind to local address to listen for DNS queries
    #bind: '127.0.0.1:5353'

    upstream {
        # Scheme list: tcp, udp, tcp+udp, https, tls, http3, h3, quic, details see above Schema.
        # If host is a domain and has both IPv4 and IPv6 record, dae will automatically choose
        # IPv4 or IPv6 to use according to group policy (such as min latency policy).
        # Please make sure DNS traffic will go through and be forwarded by dae, which is REQUIRED for domain routing.
        # If dial_mode is "ip", the upstream DNS answer SHOULD NOT be polluted, so domestic public DNS is not recommended.

        alidns: 'udp://dns.alidns.com:53'
        googledns: 'tcp+udp://dns.google:53'

        # alih3: 'h3://dns.alidns.com:443'
        # alih3_path: 'h3://dns.alidns.com:443/dns-query'
        # alihttp3: 'http3://dns.alidns.com:443'
        # alihttp3_path: 'http3://dns.alidns.com:443/dns-query'
        # ali_quic: 'quic://dns.alidns.com:853'

        # h3_custom_path: 'h3://dns.example.com:443/custom-path'
        # http3_custom_path: 'http3://dns.example.com:443/custom-path'

        # ali_doh: 'https://dns.alidns.com:443'
        # ali_dot: 'tls://dns.alidns.com:853'

        # doh_custom_path: 'https://dns.example.com:443/custom-path'
    }
    # The routing format of 'request' and 'response' is similar with section 'routing'.
    # See https://github.com/daeuniverse/dae/blob/main/docs/en/configuration/routing.md
    routing {
        # According to the request of dns query, decide to use which DNS upstream.
        # Match rules from top to bottom.
        request {
            # Built-in outbounds in 'request': asis, reject.
            # asis queries the server the request was addressed to, always over UDP.
            # Do not point other LAN devices at dae:53 (loop risk).
            # You can also use user-defined upstreams.

            # Available functions for ordinary DNS requests: qname, qtype.
            # Additional internal dae selectors in the same block: sub, node, subnode.
            # - sub(): subscription fetch requests
            # - node(): node host resolution requests
            # - subnode(): node host resolution requests for subscription-derived nodes
            #   and it is checked before node()
            # Internal selectors:
            # - only affect dae's own DNS lookups
            # - must target names defined in dns.upstream
            # - do not use fallback
            # - cannot be mixed with qname/qtype in the same rule

            # DNS request name (omit suffix dot '.').
            qname(geosite:category-ads-all) -> reject
            qname(geosite:google@cn) -> alidns # Also see: https://github.com/v2fly/domain-list-community#attributes
            qname(suffix: abc.com, keyword: google) -> googledns
            qname(full: ok.com, regex: '^yes') -> googledns
            # DNS request type
            qtype(a, aaaa) -> alidns
            qtype(cname) -> googledns
            # disable ECH to avoid affecting traffic split
            qtype(https) -> reject

            # Route dae's own subscription fetch DNS to googledns.
            # sub(my_sub) -> googledns
            # Route all nodes with "hk" in their name to googledns.
            # node(name_keyword: hk) -> googledns
            # Use alidns for nodes from subscription "my_sub" before node() rules are checked.
            # subnode(subtag: my_sub) -> alidns

            # If no match, fallback to this upstream.
            fallback: asis
        }
        # According to the response of dns query, decide to accept or re-lookup using another DNS upstream.
        # Match rules from top to bottom.
        response {
            # Built-in outbounds in 'response': accept, reject.
            # You can use user-defined upstreams.

            # Available functions: qname, qtype, upstream, ip.
            # Accept the response if the request is sent to upstream 'googledns'. This is useful to avoid loop.
            upstream(googledns) -> accept
            # If DNS request name is not in CN and response answers include private IP, which is most likely polluted
            # in China mainland. Therefore, resend DNS request to 'googledns' to get correct result.
            ip(geoip:private) && !qname(geosite:cn) -> googledns
            fallback: accept
        }
    }

}
```

`ipversion_prefer` 不会让 dae 主动查询首选的地址族。设置 `ipversion_prefer: 4` 时，只有 dae 已经知道该域名有 `A` 记录，才会把 `AAAA` 响应替换成空的 `NOERROR` 回复。已知有 `A` 记录指两种情况之一：缓存中存在未过期的 `A` 响应；或者 `AAAA` 响应最多等待 50 ms（RFC 8305 的解析延迟），在此期间收到了带记录的 `A` 响应。否则 dae 原样返回 `AAAA` 响应。`ipversion_prefer: 6` 的行为相同，只是两个地址族对调。

`fixed_domain_ttl` 设为 `0` 不会关闭缓存。dae 仍会保存响应，并把缓存截止时间设为收到响应的时刻，因此该条目在下次查询时已经过期。`optimistic_cache` 默认为 `true`。因此在 `optimistic_cache_ttl`（默认 `60` 秒；`0` 表示不限）内，dae 用这条过期条目回答后续查询，并在后台向上游刷新一次。回复中的记录 TTL 不超过 `optimistic_stale_reply_ttl`（默认 `30`）。设置 `optimistic_cache: false` 后，该域名的每次查询都同步发往上游。

## 引导解析器（`global`）

三类查询由 dae 直接发往 `global.bootstrap_resolver`，从不经过代理。第一类是 `dns.upstream` 中非 IP 字面量条目的主机名。第二类是 `dial_mode: domain`（默认值）对嗅探到的域名执行的后台探测，前提是 dae 的 DNS 缓存中没有该域名的 `A` 或 `AAAA` 记录。`domain+` 和 `domain++` 跳过该探测；`ip` 从不按域名建立连接。`dial_mode` 只接受 `ip`、`domain`、`domain+` 和 `domain++`。

第三类在 `dns.routing.request` 含有任何规则时生效，此时 dae 的内部 DNS 路由已启用。当没有 `sub()`、`node()` 或 `subnode()` 规则把订阅 URL 的主机或某个节点的服务器主机名分配给上游，或者分配到的上游未返回地址时，dae 通过引导解析器解析该主机名。这些查询绕过 `qname` 和 `qtype` 规则，并且在 DNS 路由运行期间随时发生，不只在启动时。

未设置时，dae 依次尝试 `119.29.29.29:53` 和 `223.5.5.5:53`。设置后只使用指定的解析器，完全替代这两个默认值。中国大陆以外的主机通常应选择距离更近的解析器：

```shell
global {
  bootstrap_resolver: '9.9.9.9:53'
}
```

## 模板

根据所需的 DNS 行为选择一种模板。

```shell
# Use alidns for China mainland domains and googledns for others.
dns {
  upstream {
    googledns: 'tcp+udp://dns.google:53'
    alidns: 'udp://dns.alidns.com:53'
  }
  routing {
    # According to the request of dns query, decide to use which DNS upstream.
    # Match rules from top to bottom.
    request {
      # Lookup China mainland domains using alidns, otherwise googledns.
      qname(geosite:cn) -> alidns
      # fallback is also called default.
      fallback: googledns
    }
  }
}
```

```shell
# Use alidns for all DNS queries and fallback to googledns if pollution result detected.
dns {
  upstream {
    googledns: 'tcp+udp://dns.google:53'
    alidns: 'udp://dns.alidns.com:53'
  }
  routing {
    # According to the request of dns query, decide to use which DNS upstream.
    # Match rules from top to bottom.
    request {
      # fallback is also called default.
      fallback: alidns
    }
    # According to the response of dns query, decide to accept or re-lookup using another DNS upstream.
    # Match rules from top to bottom.
    response {
      # Trusted upstream. Always accept its result.
      upstream(googledns) -> accept
      # Possibly polluted, re-lookup using googledns.
      ip(geoip:private) && !qname(geosite:cn) -> googledns
      # fallback is also called default.
      fallback: accept
    }
  }
}
```
