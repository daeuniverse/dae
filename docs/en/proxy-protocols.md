# Proxy Protocols

> **Note**: dae currently supports the following proxy protocols

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

  ShadowTLS v3 links can also be used directly with `shadowtls://`.
  For nodes that require a browser-like TLS fingerprint, set `global.tls_implementation: utls`
  and keep `global.utls_imitate` at the default `chrome_auto`, or append
  `tlsImplementation=utls&utlsImitate=chrome` in the link query.
  If the provider expects no custom SNI, omit `sni` or keep it explicitly empty.

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

  [Hysteria2 URI Schema](https://v2.hysteria.network/docs/developers/URI-Scheme)

- [x] AnyTLS

  [AnyTLS URI Schema](https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md)

- [x] Proxy chain (flexible protocol)

  [Proxy chain URI Schema](https://github.com/daeuniverse/dae/discussions/236)

For other requirements, one way to expand protocol support is by using external proxy programs. Below is an example of using the external naiveproxy.

Although dae and other proxy programs support the HTTPS protocol, using them does not utilize the chromium networking stack, which weakens the camouflage effect of naiveproxy. Therefore, using an external naiveproxy program is recommended.

1. Start naiveproxy:

   The example uses naiveproxy to open an HTTP listening port. Note that HTTP proxy does not support proxying UDP traffic, so if you are using an external proxy program, it is advisable to prioritize using the socks5 port.

   ```bash
   naiveproxy --listen=http://127.0.0.1:1090 --proxy=https://yourlink
   ```

2. In the section of dae's configuration related to nodes, add the following line: `http://127.0.0.1:1090`, and remember to use this node in the group you are using.

3. If you have bound the WAN interface, meaning you have filled in the `global.wan_interface` field, make sure to add the following line near the top in the routing section to prevent traffic from flowing back to dae after passing through naiveproxy, causing a loop:

   ```shell
   pname(naiveproxy) -> must_direct
   ```

   Here, `pname` refers to the process name. You can determine the process name of naiveproxy by examining the command used to start it, running the `ps -ef` command at runtime, or observing the dae logs. The meaning of `must_direct` is to allow all traffic, including DNS queries, to pass through directly without redirecting to dae.

   Users who only bind the LAN interface do not need to perform this step.

## Compatibility notes

### VLESS with XTLS Vision and malformed ServerHello

XTLS Vision can only be enabled once the client has read the cipher suite out
of the server's `ServerHello`: the Vision padding strategy is derived from it,
so guessing the suite would corrupt the stream. The VLESS implementation in the outbound layer therefore parses the cipher
suite only when the handshake message
is well formed, in particular when `legacy_session_id` is inside the RFC 8446
section 4.1.2 bound of 0..32 bytes and the message is long enough to contain
the field.

On a malformed `ServerHello` (session ID longer than 32 bytes, truncated or
oversized handshake) the cipher suite is left unset, **XTLS Vision is not
enabled for that connection and the session falls back to a plain VLESS
relay**: no Vision padding is applied and no protocol error is raised. The
fail-safe direction is deliberate, because inferring a cipher suite from a
malformed message would produce wrong padding and break the stream.

This behavior lives in the outbound library that dae depends on; dae itself
never parses the handshake.

### Congestion control override on QUIC-based protocols

The `tuic`, `juicity` and `hysteria2` node links accept a client-local
`cc_override` query parameter that selects which congestion controller the
client installs. It is never sent to the server, and it takes precedence over
whatever controller the server reports:

```
tuic://<uuid>:<password>@<server>:<port>?congestion_control=bbr&cc_override=bbr3
juicity://<uuid>:<password>@<server>:<port>?congestion_control=bbr&cc_override=bbr3
hysteria2://<auth>:<password>@<server>:443?upmbps=20&downmbps=100&cc_override=bbr3
```

`tuic` and `juicity` accept `bbr`, `cubic`, `new_reno`, `brutal` and `bbr3`;
`hysteria2` accepts `bbr`, `brutal` and `bbr3`. The value is lowercased and
trimmed before it is matched, and an unsupported value fails the node when the
dialer is constructed instead of silently falling back.

With no `cc_override`, these three protocols install `bbr3`; write
`cc_override=bbr` on a link to restore the previous stable default for that node.
