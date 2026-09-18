# 代理协议

dae 支持以下代理协议：

| 协议 | 支持细节 | URI 格式 |
| --- | --- | --- |
| HTTP(S)、naiveproxy | — | [HTTP(S)](#https) |
| Socks | **版本**： Socks4 / Socks4a / Socks5 | [Socks](#socks) |
| VMess / VLESS | **VMess**： AEAD, alterID=0<br>**传输**： TCP / WS / gRPC / Meek / HTTPUpgrade<br>**TLS**：支持 Reality | [v2rayN](https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2))<br>[DuckSoft](https://github.com/XTLS/Xray-core/discussions/716) |
| Shadowsocks | **加密**： AEAD / Stream Ciphers<br>**插件**： simple-obfs / shadow-tls (SIP003)，参阅[插件说明](#shadowsocks-插件) | [SIP002](https://shadowsocks.org/doc/sip002.html)<br>[SIP008](https://shadowsocks.org/doc/sip008.html) |
| ShadowsocksR | — | — |
| Trojan | Trojan-gfw / Trojan-go | [trojan/trojan-go](https://p4gefau1t.github.io/trojan-go/developer/url) |
| Tuic | **版本**： v5 | [Tuic](https://github.com/daeuniverse/dae/discussions/182) |
| Juicity | — | [Juicity](https://github.com/juicity/juicity?tab=readme-ov-file#link-format) |
| Hysteria2 | — | [Hysteria2](https://v2.hysteria.network/docs/developers/URI-Scheme) |
| AnyTLS | — | [AnyTLS](https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md) |
| 代理链（灵活协议） | — | [Proxy chain](https://github.com/daeuniverse/dae/discussions/236) |

表中协议均已支持。“—”表示原文未列出细分信息或 URI 参考链接。

## URI 示例

### HTTP(S)

  ```
  https://[[user:]pass@]hostname:port/
  ```

### Socks

  ```
  socks4://[[user:]pass@]hostname:port/
  socks5://[[user:]pass@]hostname:port/
  ```

## Shadowsocks 插件

v2ray-plugin 未标记为支持，但其 Websocket（+TLS）子项已标记为支持。

ShadowTLS v3 链接也可直接使用 `shadowtls://`。

需要浏览器式 TLS 指纹的节点可采用以下任一配置方式：

- 设置 `global.tls_implementation: utls`，并保留 `global.utls_imitate` 的默认值 `chrome_auto`。
- 在链接的查询参数中附加 `tlsImplementation=utls&utlsImitate=chrome`。

如果提供商要求不使用自定义 SNI，请省略 `sni`，或将其值明确设为空。

## 外部代理程序

可使用外部代理程序扩展协议支持。以下以 naiveproxy 为例。

dae 和其他代理程序虽支持 HTTPS 协议，却不使用 Chromium 网络栈，因而会削弱 naiveproxy 的伪装效果。因此，建议使用外部 naiveproxy 程序。

1. 启动 naiveproxy：

   本示例让 naiveproxy 监听 HTTP 端口。HTTP 代理不支持 UDP 流量，因此使用外部代理程序时，建议优先使用 SOCKS5 端口。

   ```bash
   naiveproxy --listen=http://127.0.0.1:1090 --proxy=https://yourlink
   ```

2. 在 dae 配置的节点部分添加 `http://127.0.0.1:1090`，并在所用组中使用此节点。

3. 若已绑定 WAN 接口，即填写了 `global.wan_interface`，请在 `routing` 部分靠前的位置添加以下规则。这可防止流量经 naiveproxy 后回到 dae，造成环路：

   ```shell
   pname(naiveproxy) -> must_direct
   ```

   此处 `pname` 匹配进程名。可通过查看启动命令、运行时执行 `ps -ef` 命令，或查看 dae 日志确定 naiveproxy 的进程名。

   `must_direct` 表示允许包括 DNS 查询在内的全部流量直接通过，不重定向至 dae。

   仅绑定 LAN 接口的用户无需执行此步骤。

## 兼容性说明

### VLESS 的 XTLS Vision 与格式错误的 ServerHello

flow 为 `xtls-rprx-vision` 时，客户端从第一次写入起就发送 Vision 帧：先是填充头，随后是随机填充。TLS 负载短于 900 字节时，会填充到总长 900 至 1399 字节；其他负载填充 0 至 255 字节。这种帧格式不等待服务器的 `ServerHello`。从 `ServerHello` 读取的密码套件只决定客户端随后是否切换到 XTLS direct 模式；在该模式下，客户端把内层 TLS 记录直接写入底层连接。

出站层的 VLESS 实现在完成本地边界检查后，才从 `ServerHello` 读取密码套件。读到的数据块从记录起始处算起必须至少有 79 字节，记录长度字段加 5 必须不小于 79。`legacy_session_id` 长度必须符合 RFC 8446 第 4.1.2 节规定的 0 至 32 字节范围，密码套件的两个字节必须落在该数据块内。解析器不校验 24 位握手长度，不限制记录长度上限，也不等待整条记录到齐。

如果某项检查失败，例如会话 ID 超过 32 字节，或数据块太短而放不下密码套件，则不设置密码套件。`ServerHello` 协商出 TLS 1.2，或密码套件不是 TLS 1.3 套件，或密码套件为 `TLS_AES_128_CCM_8_SHA256` 时，同样跳过 direct 模式。此后客户端一旦写入 TLS 应用数据，或过滤器检查过 6 个数据包，就用命令 `0x01`（填充结束）结束填充阶段；该帧本身仍带填充。之后的流量在外层 TLS 之上的 Vision 流中不加填充地转发，也不报告协议错误。

此行为由 dae 依赖的出站库实现；dae 本身不解析握手消息。

### 覆盖基于 QUIC 的协议的拥塞控制算法

`tuic`、`juicity` 和 `hysteria2` 节点链接支持仅作用于客户端的 `cc_override` 查询参数，用于选择客户端使用的拥塞控制算法。该参数不会发送给服务器。在 `tuic` 和 `juicity` 上，它优先于链接的 `congestion_control` 参数；在 `hysteria2` 上，它优先于服务器应答的 `rx`：

```
tuic://<uuid>:<password>@<server>:<port>?congestion_control=bbr&cc_override=bbr3
juicity://<uuid>:<password>@<server>:<port>?congestion_control=bbr&cc_override=bbr3
hysteria2://<auth>:<password>@<server>:443?upmbps=20&downmbps=100&cc_override=bbr3
```

| 协议 | `cc_override` 支持的值 |
| --- | --- |
| `tuic`、`juicity` | `bbr`、`cubic`、`new_reno`、`brutal`、`bbr3` |
| `hysteria2` | `bbr`、`brutal`、`bbr3` |

匹配前会将参数值转为小写，并去除首尾空白。如果参数值不受支持，节点会在构造 dialer 时失败，而不是静默回退。在 `tuic` 和 `juicity` 上，只有 `brutal` 和 `bbr3` 会安装各自的 sender；`bbr`、`cubic` 和 `new_reno` 安装的都是同一个 BBR sender，因为出站库没有 CUBIC 和 NewReno 实现。`cc_override=brutal` 只在已知发送速率时才安装 Brutal：在 `tuic` 和 `juicity` 上，链接必须带有正值的 `cwnd`（单位为每秒字节数）；在 `hysteria2` 上，必须按下文所述声明正值的上传速率。没有速率时，连接会安装 BBR（不是 `bbr3`），既不报错，也不写日志。

未设置 `cc_override` 时，`tuic` 和 `juicity` 只在链接设置了 `congestion_control=brutal` 且 `cwnd` 为正值时安装 `brutal`。其他情况一律安装 `bbr3`。`hysteria2` 在服务器未应答 `rx=auto` 且已声明上传速率时，按服务器 `rx` 与客户端上传速率中的较小者安装 `brutal`；否则安装 `bbr3`。上传速率来自链接的 `upmbps` 与 `downmbps`，或 `maxTx` 与 `maxRx`，否则来自全局的 `bandwidth_max_tx` 与 `bandwidth_max_rx`；每对参数必须两个值都设置。在链接中添加 `cc_override=bbr`，可为该节点恢复先前稳定版本的默认算法。
