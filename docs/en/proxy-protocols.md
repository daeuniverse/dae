# Proxy Protocols

> **Note**: dae currently supports the following proxy protocols

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
  - [x] h2
- [x] Shadowsocks
  - [x] AEAD Ciphers
  - [x] Stream Ciphers
  - [x] simple-obfs
  - [ ] v2ray-plugin
- [x] ShadowsocksR
- [x] Trojan
  - [x] Trojan-gfw
  - [x] Trojan-go
- [x] [Tuic (v5)](https://github.com/daeuniverse/dae/discussions/182)
- [x] [Juicity](https://github.com/juicity/juicity)
- [x] [Proxy chain (flexible protocol)](https://github.com/daeuniverse/dae/discussions/236)

For other requirements, one way to expand protocol support is by using external proxy programs. Below is an example of using the external naiveproxy.

Although dae and other proxy programs support the HTTPS protocol, using them does not utilize the chromium networking stack, which weakens the camouflage effect of naiveproxy. Therefore, using an external naiveproxy program is recommended.

1. Start naiveproxy:

   Since the socks implementation of naiveproxy may have some issues and cannot be used by curl and dae, the example uses naiveproxy to open an HTTP listening port. Note that HTTP proxy does not support proxying UDP traffic, so if you are using an external proxy program, it is advisable to prioritize using the socks5 port.

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
