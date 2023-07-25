# Global

dae 的全局配置，主要控制 dae 除 DNS 和 routing 之外的行为，以下为示例。

## 示例

```shell
global {
    ##### 软件选项。

    # 监听的 tproxy 端口。不是 HTTP/SOCKS 端口，仅供 eBPF 程序使用.
    # 一般情况下，你不需要使用它。
    tproxy_port: 12345

    # 设为 true 来避免意外的流量进入 tproxy 端口。 设为 false 以配合用户自定义的 iptables tproxy 规则。
    tproxy_port_protect: true

    # 若非 0，dae 发出的流量会打上 SO_MARK。 这有助于使用 iptables tproxy 规则时避免流量回环。
    so_mark_from_dae: 0

    # 日志等级: error, warn, info, debug, trace。
    log_level: info

    # 禁用等待网络以拉取订阅。
    disable_waiting_network: false


    ##### 接口和内核选项。

    # 绑定的 LAN 接口。使用它来代理局域网设备。
    # 多个接口使用 "," 分隔。
    #lan_interface: docker0

    # 绑定的 WAN 接口. 使用它来代理本机。
    # 多个接口使用 "," 分隔。使用 "auto" 自动检测接口.
    wan_interface: auto

    # 自动配置 Linux 的内核选项（如 ip_forward 和 send_redirects）。
    # 参考https://github.com/daeuniverse/dae/blob/main/docs/en/user-guide/kernel-parameters.md
    auto_config_kernel_parameter: true


    ##### 节点连通性检测。

    # 如果你本地网络为双栈，URL的主机应该同时支持 IPv4 和 IPv6。
    # 第一个是 URL，如果在其后填写了 IP 地址，代表对 URL 中 Host 的固定解析。
    # 考虑到流量消耗，推荐使用具有任播且响应简短的站点。
    #tcp_check_url: 'http://cp.cloudflare.com'
    tcp_check_url: 'http://cp.cloudflare.com,1.1.1.1,2606:4700:4700::1111'

    # 用于 `tcp_check_url` 的 HTTP 请求方法。 默认使用 'HEAD'，因为一些服务器实现不统计该类型流量。
    tcp_check_http_method: HEAD

    # 该 DNS 用于检测节点的 UDP 连通性。若包含 tcp 的 DNS，同样用于检测节点的 TCP DNS 连通性。
    # 第一个是 URL，如果在其后填写了 IP 地址，代表对 URL 中 Host 的固定解析。
    # 如果你本地网络为双栈，DNS 服务器应同时支持 IPv4 和 IPv6。
    #udp_check_dns: 'dns.google.com:53'
    udp_check_dns: 'dns.google.com:53,8.8.8.8,2001:4860:4860::8888'

    # 检测间隔
    check_interval: 30s

    # 仅在 new_latency <= old_latency - tolerance 时组内切换节点。
    check_tolerance: 50ms


    ##### 连接选项。

    # dial_mode 选项为:
    # 1. "ip"。 使用 DNS 查询得到的 IP 直接发送代理。这允许 ipv4、ipv6 分别选择最佳路径，并使应用程序请求的 IP 版本满足预期。
    #       例如，如果使用 curl-4 ip.sb，将通过代理请求 IPv4 并获得 IPv4 响应。curl-6 ip.sb 将请求 IPv6。若节点支持IPv6，
    #       这可能会解决一些奇怪的全锥问题。在此模式下将禁用嗅探。
    # 2. "domain"。 使用嗅探到的域名发送代理。若 DNS 环境不纯净，这将在很大程度上缓解 DNS 污染问题。通常，这种模式会带来更快的
    #       代理响应，因为代理会在远程重新解析域名，从而获得更好的 IP 连接结果。此策略不影响路由，也就是说，域名重写将在路由的
    #       流量拆分后进行， dae 不会重新路由。
    # 3. "domain+"。 基于 domain 模式但不会检查嗅探得到域名的真实性。 对于 DNS 请求不经过 dae 但想要更快的代理响应的用户有用。
    #       但是， 若 DNS 请求不经过 dae，基于域名的流量拆分将失效。
    # 4. "domain++"。 基于 domain+ 模式但会根据嗅探到的域名重新进行流量路由，以部分恢复基于域名的流量拆分能力。对于直连流量无效
    #       且会占用更多的 CPU 资源。
    dial_mode: domain

    # 允许不安全的 TLS 证书. 非须勿用.
    allow_insecure: false

    # 嗅探第一个数据的超时。若 dial_mode 为 ip 则该值总为 0。若局域网延迟较高，应调高它。
    sniffing_timeout: 100ms

    # TLS 实现. 设为 tls 以使用 Go's crypto/tls。设为 utls 以使用 uTLS, 可以模拟浏览器的 Client Hello、
    tls_implementation: tls

    # uTLS 模拟的 Client Hello ID。 仅在 tls_implementation 设为 utls时 生效。
    # 参考: https://github.com/daeuniverse/dae/blob/331fa23c16/component/outbound/transport/tls/utls.go#L17
    utls_imitate: chrome_auto
}
```
