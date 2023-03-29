# 其他代理协议

dae 目前支持的代理协议有：

- [x] HTTP(S), naiveproxy
- [x] Socks
  - [x] Socks4
  - [x] Socks4a
  - [x] Socks5
- [x] VMess(AEAD, alterID=0) / VLESS
  - [x] TCP
  - [x] WS
  - [x] TLS
  - [x] gRPC
- [x] Shadowsocks
  - [x] AEAD Ciphers
  - [x] Stream Ciphers
  - [x] simple-obfs
  - [ ] v2ray-plugin
- [x] ShadowsocksR
- [x] Trojan
  - [x] Trojan-gfw
  - [x] Trojan-go

有其他需求的，一种方式是通过外接其他代理程序来扩展协议支持。下面给出外接 naiveproxy 的例子。

尽管 dae 等代理程序支持 https 协议，但由于并不使用 chromium 网络栈，削弱了 naiveproxy 的伪装效果，因此可以选择外接 naiveproxy 程序来实现。

1. 启动 naiveproxy：

   由于 naiveproxy 的 socks 实现可能有些问题，无法被 curl 和 dae 使用，样例中使用 naiveproxy 开启一个 http 监听端口。注意，http 代理不支持代理 udp 流量，所以如果你外接其他代理程序，建议优先考虑使用 socks5 端口。

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
