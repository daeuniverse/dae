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
    - [x] Reality
  - [x] gRPC
  - [x] Meek
  - [x] HTTPUpgrade

  [v2rayN URI Schema](https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2))

  [DuckSoft URI Schema](https://github.com/XTLS/Xray-core/discussions/716)

- [x] Shadowsocks
  - [x] AEAD Ciphers
  - [x] Stream Ciphers
  - [x] simple-obfs
  - [x] shadow-tls (SIP003 plugin)
  - [ ] v2ray-plugin
    - [x] Websocket (+TLS)

  ShadowTLS v3 链接也可以直接使用 `shadowtls://`。
  对于需要浏览器指纹的节点，建议设置 `global.tls_implementation: utls`，
  并保持 `global.utls_imitate` 默认值 `chrome_auto`，或者在链接查询参数中追加
  `tlsImplementation=utls&utlsImitate=chrome`。
  如果服务端不希望带自定义 SNI，请省略 `sni`，或明确写成空值。

  [SIP002](https://shadowsocks.org/doc/sip002.html)

  [SIP008](https://shadowsocks.org/doc/sip008.html)

- [x] ShadowsocksR

- [x] Trojan
  - [x] Trojan-gfw
  - [x] Trojan-go

  [trojan/trojan-go URI Schema](https://p4gefau1t.github.io/trojan-go/developer/url)

- [x] Tuic (v5)

  [Tuic URI Schema](https://github.com/daeuniverse/dae/discussions/182)

- [x] Juicity

  [Juicity URI Schema](https://github.com/juicity/juicity?tab=readme-ov-file#link-format)

- [x] Hysteria2

  [Hysteria2 URI Schema](https://v2.hysteria.network/zh/docs/developers/URI-Scheme)

- [x] AnyTLS

  [AnyTLS URI Schema](https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md)

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

## 兼容性说明

### VLESS XTLS Vision 与畸形 ServerHello

XTLS Vision 只有在客户端从服务端 `ServerHello` 中读出密码套件后才能启用：Vision 的填充策略由该套件决定，猜测套件会破坏数据流。因此 outbound 层中的 VLESS 实现仅在握手消息格式正确时解析密码套件，即 `legacy_session_id` 长度在 RFC 8446 第 4.1.2 节允许的 0..32 字节范围内、且消息长度足以包含该字段时。

当 `ServerHello` 畸形（session ID 超过 32 字节、握手被截断或超长）时，密码套件保持未设置，**该连接不会启用 XTLS Vision，而是退回普通 VLESS 中继**：不施加 Vision 填充，也不产生协议错误。这个失败方向是刻意选择的：从畸形消息推断密码套件会给出错误的填充，直接破坏连接。

该行为位于 dae 依赖的 outbound 库中；dae 自身不解析该握手。

### 基于 QUIC 的协议的拥塞控制覆盖

`tuic`、`juicity`、`hysteria2` 节点链接支持客户端本地的 `cc_override` 查询参数，用于指定客户端安装的拥塞控制算法。该参数不会发送给服务端，且优先于服务端下发的算法：

```
tuic://<uuid>:<password>@<server>:<port>?congestion_control=bbr&cc_override=bbr3
juicity://<uuid>:<password>@<server>:<port>?congestion_control=bbr&cc_override=bbr3
hysteria2://<auth>:<password>@<server>:443?upmbps=20&downmbps=100&cc_override=bbr3
```

`tuic` 与 `juicity` 支持 `bbr`、`cubic`、`new_reno`、`brutal`、`bbr3`；`hysteria2` 支持 `bbr`、`brutal`、`bbr3`。取值在匹配前统一转为小写并去除首尾空白；不受支持的值会在构造 dialer 时使该节点直接失败，而不是静默回退。

不设置 `cc_override` 时，这三个协议安装 `bbr3`；在链接上写 `cc_override=bbr` 可让该节点恢复此前的稳定默认。
