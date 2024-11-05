# 其他代理协议

> **Note**: dae 目前支持以下代理协议

- [x] HTTP(S), naiveproxy
  ```
  https://[[user:]pass@]hostname:port/
  ```
- [x] Socks
  - [x] Socks4
  - [x] Socks4a
  - [x] Socks5

  ```
  socks4://[[user:]pass@]hostname:port/
  socks5://[[user:]pass@]hostname:port/
  ```

- [x] VMess(AEAD, alterID=0) / VLESS
  - [x] TCP
  - [x] WS
  - [x] TLS
    - [x] Reality (**实验性，目前仅支持 TCP**)
  - [x] gRPC
  - [x] Meek
  - [x] HTTPUpgrade

  [v2rayN URI Schema](https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2))

  [DuckSoft URI Schema](https://github.com/XTLS/Xray-core/discussions/716)

- [x] Shadowsocks
  - [x] AEAD Ciphers
  - [x] Stream Ciphers
  - [x] simple-obfs
  - [ ] v2ray-plugin
    - [x] Websocket (+TLS)

  [SIP002](https://shadowsocks.org/doc/sip002.html)

  [SIP008](https://shadowsocks.org/doc/sip008.html)

- [x] ShadowsocksR

- [x] Trojan
  - [x] Trojan-gfw
  - [x] Trojan-go

  [trojan/trojan-go URI Schema](https://p4gefau1t.github.io/trojan-go/developer/url/)

- [x] Tuic (v5)

  [Tuic URI Schema](https://github.com/daeuniverse/dae/discussions/182)

- [x] Juicity

  [Juicity URI Schema](https://github.com/juicity/juicity?tab=readme-ov-file#link-format)

- [x] Hysteria2

  [Hysteria2 URI Schema](https://v2.hysteria.network/zh/docs/developers/URI-Scheme)

- [x] Proxy chain (flexible protocol)

  [Proxy chain URI Schema](https://github.com/daeuniverse/dae/discussions/236)

有其他需求的，一种方式是通过外接其他代理程序来扩展协议支持。下面给出外接 naiveproxy 的例子。

尽管 dae 等代理程序支持 HTTPS 协议，但由于并不使用 chromium 网络栈，削弱了 naiveproxy 的伪装效果，因此可以选择外接 naiveproxy 程序来实现。

1. 启动 naiveproxy：

   样例使用 naiveproxy 开启一个 HTTP 监听端口。注意，HTTP 代理不支持代理 udp 流量，所以如果你外接其他代理程序，建议优先考虑使用 socks5 端口。

   ```bash
   naiveproxy --listen=http://127.0.0.1:1090 --proxy=https://yourlink
   ```

2. 在 dae 配置的 node 一节中，新增一行：`http://127.0.0.1:1090`，并记得在所使用的组中使用该节点。

3. 如果你绑定了 WAN 接口，即在 `global.wan_interface` 填写了内容，确保在 routing 一节的靠上位置增加一行，以避免流量从 dae 流向 naiveproxy 之后再次流向 dae，造成回环：

   ```shell
   pname(naiveproxy) -> must_direct
   ```

   这里的 pname 的含义是进程名。你可通过启动时的命令，或运行时通过 `ps -ef` 命令或者观察 dae 的日志来确定 naiveproxy 的进程名。must_direct 的含义是所有流量，包括 dns 查询都放行直连，不重定向至 dae。

   只绑定 LAN 接口的用户不需要做这一步。
