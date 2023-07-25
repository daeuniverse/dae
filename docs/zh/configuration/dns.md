# DNS

dae 会拦截目标为端口53的所有 UDP 流量并嗅探 DNS, 以下是一些DNS配置的示例和模板.

## 示例

```shell
dns {
    # 若 ipversion_prefer 设为 4，且域名同时有 A 和 AAAA 记录，dae 只回应 A 类型的请求，并返回空回复给 AAAA 请求。
    ipversion_prefer: 4

    # 为域名设定固定的 ttl。若设为 0，dae 不缓存该域名 DNS 记录，收到请求时每次向上游查询。
    fixed_domain_ttl {
        ddns.example.org: 10
        test.example.org: 3600
    }

    upstream {
        # 格式为“协议://主机:端口”
        # 支持协议：tcp, udp, tcp+udp（对于https, tls, quic的支持孵化中）。
        # 若主机为域名且具有 A 和 AAAA 记录，dae 自动选择 IPv4 或 IPv6 进行连接,
        # 是否走代理取决于全局的 routing（不是下面 dns 配置部分的 routing），节点选择取决于 group 的策略。
        # 请确保DNS流量经过dae且由dae转发，按域名分流需要如此！
        # 若 dial_mode 设为 'ip'，请确保上游 DNS 无污染，不推荐使用国内公共 DNS。

        alidns: 'udp://dns.alidns.com:53'
        googledns: 'tcp+udp://dns.google.com:53'
    }
    # 'request' 和 'response' 的 routing 格式和全局的 'routing' 类似。
    # 参考 https://github.com/daeuniverse/dae/blob/main/docs/zh/configuration/routing.md
    routing {
        # 根据 DNS 查询，决定使用哪个 DNS 上游。
        # 按由上到下的顺序匹配。
        request {
            # 'request' 具有预置出站：asis, reject。
            # asis 即向收到的 DNS 请求中的目标服务器查询，请勿将其他局域网设备 DNS 服务器设为 dae:53（小心回环）。
            # 你可以使用在 upstream 中配置的 DNS 上游。

            # 可以使用: qname, qtype。

            # DNS 查询域名（省略后缀点 '.'）。
            qname(geosite:category-ads-all) -> reject
            qname(geosite:google@cn) -> alidns # 参考: https://github.com/v2fly/domain-list-community#attributes
            qname(suffix: abc.com, keyword: google) -> googledns
            qname(full: ok.com, regex: '^yes') -> googledns
            # DNS 查询类型
            qtype(a, aaaa) -> alidns
            qtype(cname) -> googledns

            # fallback 意为 default。
            # 如果上面的都不匹配，使用这个 upstream。
            fallback: asis
        }
        # 根据 DNS 查询的回复， 决定接受或使用其他 upstream 重新查询。
        # 按由上到下的顺序匹配。
        response {
            # 具有预置出站：accept, reject。
            # 你可以使用在 upstream 中配置的 DNS 上游。

            # 可以使用: qname, qtype, upstream, ip。
            # 接受upstream 'googledns' 回复的 DNS 响应。 有助于避免回环。
            upstream(googledns) -> accept
            # 若 DNS 请求的域名不属于 CN 且回复包含私有 IP， 大抵是被污染了，向 'googledns' 重查。
            !qname(geosite:cn) && ip(geoip:private) -> googledns
            fallback: accept
        }
    }

}
```

## 模板

```shell
# 对于中国大陆域名使用 alidns，其他使用 googledns 查询。
dns {
  upstream {
    googledns: 'tcp+udp://dns.google.com:53'
    alidns: 'udp://dns.alidns.com:53'
  }
  routing {
    # 根据 DNS 查询，决定使用哪个 DNS 上游。
    # 按由上到下的顺序匹配。
    request {
      # 对于中国大陆域名使用 alidns，其他使用 googledns 查询。
      qname(geosite:cn) -> alidns
      # fallback 意为 default。
      fallback: googledns
    }
  }
}
```

```shell
# 默认使用 alidns，如果疑似污染使用 googledns 重查。
dns {
  upstream {
    googledns: 'tcp+udp://dns.google.com:53'
    alidns: 'udp://dns.alidns.com:53'
  }
  routing {
    # 根据 DNS 查询，决定使用哪个 DNS 上游。
    # 按由上到下的顺序匹配。
    request {
      # fallback 意为 default。
      fallback: alidns
    }
    # 根据 DNS 查询的回复， 决定接受或使用其他 upstream 重新查询。
    # 按由上到下的顺序匹配。
    response {
      # 可信的 upstream。总是接受它的回复。
      upstream(googledns) -> accept
      # 疑似被污染结果，向 'googledns' 重查。
      !qname(geosite:cn) && ip(geoip:private) -> googledns
      # fallback 意为 default。
      fallback: accept
    }
  }
}
```
