# Proxy protocols

dae supports the following proxy protocols:

| Protocol | Support details | URI schema |
| --- | --- | --- |
| HTTP(S), naiveproxy | | [HTTP(S)](#https) |
| Socks | Socks4, Socks4a, Socks5 | [Socks](#socks) |
| VMess / VLESS | VMess: AEAD, alterID=0; TCP, WS, TLS (including Reality), gRPC, Meek, HTTPUpgrade | [v2rayN](https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2)), [DuckSoft](https://github.com/XTLS/Xray-core/discussions/716) |
| Shadowsocks | AEAD ciphers, stream ciphers, simple-obfs, shadow-tls (SIP003 plugin); see [plugin notes](#shadowsocks-plugins) | [SIP002](https://shadowsocks.org/doc/sip002.html), [SIP008](https://shadowsocks.org/doc/sip008.html) |
| ShadowsocksR | | |
| Trojan | Trojan-gfw, Trojan-go | [trojan/trojan-go](https://p4gefau1t.github.io/trojan-go/developer/url) |
| Tuic | v5 | [Tuic](https://github.com/daeuniverse/dae/discussions/182) |
| Juicity | | [Juicity](https://github.com/juicity/juicity?tab=readme-ov-file#link-format) |
| Hysteria2 | | [Hysteria2](https://v2.hysteria.network/docs/developers/URI-Scheme) |
| AnyTLS | | [AnyTLS](https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md) |
| Proxy chain (flexible protocol) | | [Proxy chain](https://github.com/daeuniverse/dae/discussions/236) |

## URI examples

### HTTP(S)

  ```
  https://[[user:]pass@]hostname:port/
  ```

### Socks

  ```
  socks4://[[user:]pass@]hostname:port/
  socks5://[[user:]pass@]hostname:port/
  ```

## Shadowsocks plugins

- [ ] v2ray-plugin
  - [x] Websocket (+TLS)

ShadowTLS v3 links can also be used directly with `shadowtls://`.
For nodes that require a browser-like TLS fingerprint, set `global.tls_implementation: utls`
and keep `global.utls_imitate` at the default `chrome_auto`, or append
`tlsImplementation=utls&utlsImitate=chrome` to the link query.
If the provider expects no custom SNI, omit `sni` or keep it explicitly empty.

## External proxy programs

Use external proxy programs to extend protocol support. The following example uses external naiveproxy.

Although dae and other proxy programs support HTTPS, they do not use the Chromium networking stack. This weakens naiveproxy's camouflage, so an external naiveproxy program is recommended.

1. Start naiveproxy:

   This example opens an HTTP listening port. HTTP proxies cannot proxy UDP traffic, so prefer a Socks5 port when using an external proxy program.

   ```bash
   naiveproxy --listen=http://127.0.0.1:1090 --proxy=https://yourlink
   ```

2. Add `http://127.0.0.1:1090` to the `node` section of dae's configuration, then use this node in your group.

3. If you have set `global.wan_interface`, add the following rule near the top of the `routing` section. It prevents traffic from returning to dae after passing through naiveproxy and causing a loop:

   ```shell
   pname(naiveproxy) -> must_direct
   ```

   `pname` matches the process name. Find naiveproxy's process name in its startup command, the output of `ps -ef` while it is running, or dae's logs.

   `must_direct` sends all traffic, including DNS queries, directly without redirecting it to dae.

   Skip this step if you only bind the LAN interface.

## Compatibility notes

### VLESS with XTLS Vision and malformed ServerHello

With flow `xtls-rprx-vision`, the client sends Vision framing from its first
write: a padding header followed by random padding. A TLS payload shorter than
900 bytes is padded to a total of 900..1399 bytes; any other payload gets
0..255 bytes of padding. This framing does not wait for the server's
`ServerHello`. The cipher suite read from `ServerHello` only decides whether
the client later switches to XTLS direct mode, where the client writes inner
TLS records straight to the underlying connection.

The outbound VLESS implementation reads the cipher suite from `ServerHello`
after local bounds checks. The checks are:

- the read chunk holds at least 79 bytes from the record start
- the record length field plus 5 is at least 79
- `legacy_session_id` is within the 0..32-byte bound in RFC 8446 section 4.1.2
- the two cipher suite bytes fall inside the chunk

The parser does not validate the 24-bit handshake length, sets no upper bound
on the record length, and does not wait for the whole record to arrive.

If a check fails (a session ID longer than 32 bytes, or a chunk too short to
hold the cipher suite), the cipher suite remains unset. Direct mode is also
skipped when `ServerHello` negotiates TLS 1.2, or when the suite is not a TLS
1.3 suite or is `TLS_AES_128_CCM_8_SHA256`. Once the client writes TLS
application data, or after the filter has inspected 6 packets, the client ends
the padding phase with command `0x01` (padding end). That frame is still
padded. Later traffic is relayed without padding inside the Vision flow over
the outer TLS, and no protocol error is raised.

The behavior is implemented in dae's outbound library; dae itself never parses
the handshake.

### Congestion control override on QUIC-based protocols

The `tuic`, `juicity`, and `hysteria2` node links accept a client-local
`cc_override` query parameter that selects the client's congestion controller.
It is never sent to the server. It takes precedence over the link's
`congestion_control` parameter on `tuic` and `juicity`, and over the server's
`rx` answer on `hysteria2`:

```
tuic://<uuid>:<password>@<server>:<port>?congestion_control=bbr&cc_override=bbr3
juicity://<uuid>:<password>@<server>:<port>?congestion_control=bbr&cc_override=bbr3
hysteria2://<auth>:<password>@<server>:443?upmbps=20&downmbps=100&cc_override=bbr3
```

| Protocol | Accepted `cc_override` values |
| --- | --- |
| `tuic`, `juicity` | `bbr`, `cubic`, `new_reno`, `brutal`, `bbr3` |
| `hysteria2` | `bbr`, `brutal`, `bbr3` |

The value is lowercased and trimmed before matching. An unsupported value
causes node setup to fail when the dialer is constructed, rather than silently
falling back. On `tuic` and `juicity`, only `brutal` and `bbr3` install their
own sender; `bbr`, `cubic`, and `new_reno` all install the same BBR sender,
because the outbound library ships no CUBIC or NewReno implementation.
`cc_override=brutal` installs Brutal only when a send rate is known. On `tuic`
and `juicity`, the link must carry `cwnd=<bytes per second>` with a positive
value; on `hysteria2`, a positive upload rate must be declared as described
below. Without a rate, the connection installs BBR (not `bbr3`) with no error
and no log message.

With no `cc_override`, `tuic` and `juicity` install `brutal` when the link sets
`congestion_control=brutal` and a positive `cwnd`, and `bbr3` in every other
case. When the server does not answer `rx=auto` and an upload rate is declared,
`hysteria2` installs `brutal` at the lower of the server's `rx` and the
client's upload rate. Otherwise it installs `bbr3`. The upload rate comes from
the link's `upmbps` with `downmbps` or `maxTx` with `maxRx`, or else from the
global `bandwidth_max_tx` with `bandwidth_max_rx`; both values of a pair must
be set. Write `cc_override=bbr` on a link to restore the previous stable
default for that node.
