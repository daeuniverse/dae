# Changelogs

Also seen in [GitHub Releases](https://github.com/daeuniverse/dae/releases)

HTML version available at https://dae.v2raya.org/docs/current/changelogs

## Query history releases

```bash
curl --silent "https://api.github.com/repos/daeuniverse/dae/releases" | jq -r '.[] | {tag_name,created_at,prerelease}'
```

## Releases

<!-- BEGIN NEW TOC ENTRY -->
- [v0.2.0 (Latest)](#v020-latest)
- [0.2.0rc4 (Pre-release)](#020rc4-pre-release)
- [0.2.0rc2 (Pre-release)](#020rc2-pre-release)
- [0.2.0rc1 (Pre-release)](#020rc1-pre-release)
- [0.1.10.p1 (Current)](#0110p1-current)
- [0.1.10](#0110-current)
- [0.1.9-patch.1](#019-patch1)
- [0.1.9](#019)
- [0.1.8](#018)
- [0.1.7](#017)
- [0.1.6](#016)
- [0.1.5](#015)
- [0.1.4](#014)
- [0.1.3](#013)
- [0.1.2](#012)
- [0.1.1](#011)
- [0.1.0](#010)
<!-- BEGIN NEW CHANGELOGS -->

### v0.2.0 (Latest)

> Release date: 2023/07/02





### Bug Fixes

* fix: samba not work in [#173](https://github.com/daeuniverse/dae/pull/173) by (@mzz2017)
* fix: should allow fallbacking ip version if dialing domain in [#164](https://github.com/daeuniverse/dae/pull/164) by (@mzz2017)

### Others

* chore: expose the routable dialer for dae-wing in [#172](https://github.com/daeuniverse/dae/pull/172) by (@mzz2017)
* ci(generate-changelogs): add control on whether to write to issue page in [#170](https://github.com/daeuniverse/dae/pull/170) by (@yqlbu)
* chore(geodata): change back to v2fly geodata in [#168](https://github.com/daeuniverse/dae/pull/168) by (@mzz2017)

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.2.0rc4...v0.2.0

### 0.2.0rc4 (Pre-release)

> Release date: 2023/06/27

### Features

- optimize(routing): fix slow domain++ ip routing in [#133](https://github.com/daeuniverse/dae/pull/133) by (@mzz2017)

### Bug Fixes

- fix: bad connectivity check of dns(tcp) caused by #80 in [#155](https://github.com/daeuniverse/dae/pull/155) by (@mzz2017)
- fix/chore(grpc): allow insecure caused no connection in [#151](https://github.com/daeuniverse/dae/pull/151) by (@mzz2017)
- fix: new control plane should reset grpc conn pool cache in [#150](https://github.com/daeuniverse/dae/pull/150) by (@mzz2017)
- fix(group): policy 'fixed' parsing in [#149](https://github.com/daeuniverse/dae/pull/149) by (@mzz2017)
- fix(socks5): udp problem in [#148](https://github.com/daeuniverse/dae/pull/148) by (@mzz2017)
- fix: should gracefully exit if failed to listen when reloading in [#138](https://github.com/daeuniverse/dae/pull/138) by (@mzz2017)
- fix: change default `tcp_check_http_method` from CONNECT to `HEAD` in [#137](https://github.com/daeuniverse/dae/pull/137) by (@mzz2017)
- fix: failed to sniff tls1.2 traffic in some cases in [#135](https://github.com/daeuniverse/dae/pull/135) by (@mzz2017)
- fix: enlarge kernel geoip size limit in [#130](https://github.com/daeuniverse/dae/pull/130) by (@mzz2017)
- fix(config): problem that always append values to default list in [#128](https://github.com/daeuniverse/dae/pull/128) by (@mzz2017)
- fix/ci: fix argument list too long due to packed and use clang-15 in [#162](https://github.com/daeuniverse/dae/pull/162) by (@mzz2017)

### Others

- ci: add generate-changelogs workflow in [#159](https://github.com/daeuniverse/dae/pull/159) by (@yqlbu)
- chore/docs: support to unroll route loop and update troubleshooting.md in [#158](https://github.com/daeuniverse/dae/pull/158) by (@mzz2017)
- ci: separate release build from main build in [#157](https://github.com/daeuniverse/dae/pull/157) by (@yqlbu)
- docs(getting-started): add ref to run-as-daemon in [#147](https://github.com/daeuniverse/dae/pull/147) by (@yqlbu)
- chore(pr_template): correct a typo in [#146](https://github.com/daeuniverse/dae/pull/146) by (@yqlbu)
- chore: allow to modify app name and assets dir name in [#144](https://github.com/daeuniverse/dae/pull/144) by (@mzz2017)
- chore(Dockerfile): change geodata upstream in [#140](https://github.com/daeuniverse/dae/pull/140) by (@mzz2017)
- chore: fix incorrect number of routing rule stringer in [#131](https://github.com/daeuniverse/dae/pull/131) by (@mzz2017)
- chore: fix make with /bin/sh in [#129](https://github.com/daeuniverse/dae/pull/129) by (@mzz2017)
- chore(Makefile): support submodules in [#126](https://github.com/daeuniverse/dae/pull/126) by (@mzz2017)
- chore(changelogs-v0.2.0rc1): apply minor fix in [#125](https://github.com/daeuniverse/dae/pull/125) by (@yqlbu)
- chore(config): support IgnoreZero option for config.Marhsaller in [#153](https://github.com/daeuniverse/dae/pull/153) by (@mzz2017)

### 特性支持

- 优化(routing): 修复 domain++ 的 ip 规则匹配缓慢的问题 in [#133](https://github.com/daeuniverse/dae/pull/133) by (@mzz2017)

### 问题修复

- 修复: 由 #80 导致的无法正常工作的 TCP DNS 检查 in [#155](https://github.com/daeuniverse/dae/pull/155) by (@mzz2017)
- 修复(grpc): allow insecure 会导致的无法连接 in [#151](https://github.com/daeuniverse/dae/pull/151) by (@mzz2017)
- 修复: grpc 连接池缓存应当在 reload 时候重置 in [#150](https://github.com/daeuniverse/dae/pull/150) by (@mzz2017)
- 修复(group): 策略 'fixed' 的解析问题 in [#149](https://github.com/daeuniverse/dae/pull/149) by (@mzz2017)
- 修复(socks5): udp 无法正常工作的问题 in [#148](https://github.com/daeuniverse/dae/pull/148) by (@mzz2017)
- 修复: 重载时无法监听 tproxy 端口，应当做好清理工作后退出 in [#138](https://github.com/daeuniverse/dae/pull/138) by (@mzz2017)
- 修复: 将 `tcp_check_http_method` 的默认值从 `CONNECT` 改为 `HEAD` in [#137](https://github.com/daeuniverse/dae/pull/137) by (@mzz2017)
- 修复: 一些情况下无法嗅探 tls1.2 流量的问题 in [#135](https://github.com/daeuniverse/dae/pull/135) by (@mzz2017)
- 修复: 扩大内核程序中可放置的 geoip 大小限制 in [#130](https://github.com/daeuniverse/dae/pull/130) by (@mzz2017)
- 修复(config): 总是将用户设置的值添加到默认列表的后面的问题，例如 tcp_check_url 列表 in [#128](https://github.com/daeuniverse/dae/pull/128) by (@mzz2017)
- 修复/自动化: 修复 packed 导致的 argument list too long 并使用 clang-15 构建 in [#162](https://github.com/daeuniverse/dae/pull/162) by (@mzz2017)

### 其他变更

- 自动化: 添加生成 changelogs 工作流 in [#159](https://github.com/daeuniverse/dae/pull/159) by (@yqlbu)
- 杂项/文档: 支持编译时 unroll route loop，更新 troubleshooting.md in [#158](https://github.com/daeuniverse/dae/pull/158) by (@mzz2017)
- 自动化: 从 main build 中分离 release build in [#157](https://github.com/daeuniverse/dae/pull/157) by (@yqlbu)
- 文档(getting-started): 添加到 run-as-daemon 的引用 in [#147](https://github.com/daeuniverse/dae/pull/147) by (@yqlbu)
- 杂项(pr_template): 修正错别字 in [#146](https://github.com/daeuniverse/dae/pull/146) by (@yqlbu)
- 杂项: 允许修改 app name 和 assets dir name in [#144](https://github.com/daeuniverse/dae/pull/144) by (@mzz2017)
- 杂项(Dockerfile): 更改 geodata 上游 in [#140](https://github.com/daeuniverse/dae/pull/140) by (@mzz2017)
- 杂项: 修复不正确的 routing rule 条目数的打印 in [#131](https://github.com/daeuniverse/dae/pull/131) by (@mzz2017)
- 杂项: 修复使用 /bin/sh 会导致 make 失败的问题 in [#129](https://github.com/daeuniverse/dae/pull/129) by (@mzz2017)
- 杂项(Makefile): 支持 submodules in [#126](https://github.com/daeuniverse/dae/pull/126) by (@mzz2017)
- 杂项(changelogs-v0.2.0rc1): 修复格式问题 in [#125](https://github.com/daeuniverse/dae/pull/125) by (@yqlbu)
- 杂项(config): 为 config.Marhsaller 添加 IgnoreZero 选项支持 in [#153](https://github.com/daeuniverse/dae/pull/153) by (@mzz2017)

**Example Config**: https://github.com/daeuniverse/dae/blob/v0.2.0rc4/example.dae

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.2.0rc2...v0.2.0rc4

### 0.2.0rc2 (Pre-release)

> Release date: 2023/06/05

#### 功能变更

- fix(trojan): 修复因无效的 trojan 协议控制字段而导致的程序崩溃 by @mzz2017 in https://github.com/daeuniverse/dae/pull/120

#### Changes

- fix(dns): potential panic due to invalid packet control data by accident by @mzz2017 in https://github.com/daeuniverse/dae/pull/120

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.10...v0.2.0rc2

**Example Config**: https://github.com/daeuniverse/dae/blob/v0.2.0rc2/example.dae

### 0.2.0rc1 (Pre-release)

> Release date: 2023/06/04

#### 功能变更

- feat: 支持 iptables/nftables 的 mangle 表 tproxy by @mzz2017 in https://github.com/daeuniverse/dae/pull/80
- feat: 支持 uTLS by @AkinoKaede in https://github.com/daeuniverse/dae/pull/94
- feat: 支持在 geosite 使用属性标签 `@` 符号 by @mzz2017 in https://github.com/daeuniverse/dae/pull/98
- feat(dns): 支持为特定域名设定固定的 ttl，这对 DDNS 场景较为有用 by @mzz2017 in https://github.com/daeuniverse/dae/pull/100
- fix(dns): 修复 DNS 中 qname 匹配规则失效的问题 by @mzz2017 in https://github.com/daeuniverse/dae/pull/99
- fix: 修复启动时网络检查链接列表的随机排布问题 by @mzz2017 in https://github.com/daeuniverse/dae/pull/106
- fix(config_parser): 修复配置文件格式错误时潜在的崩溃问题 by @mzz2017 in https://github.com/daeuniverse/dae/pull/108
- fix(trojan): 修复 trojan 崩溃问题，该问题由 ReadFrom 返回的 n 可能不正确导致 by @mzz2017 in https://github.com/daeuniverse/dae/pull/109

#### 其他变更

- ci: 添加文档格式检查工作流 by @yqlbu in https://github.com/daeuniverse/dae/pull/93
- refactor: 将 insert.sh 移动至 ./hack/test by @yqlbu in https://github.com/daeuniverse/dae/pull/95
- ci(hack): 添加 config-doc-generator by @yqlbu in https://github.com/daeuniverse/dae/pull/101
- fix(test): 修复 domain_matcher/benchmark_test.go by @mzz2017 in https://github.com/daeuniverse/dae/pull/107
- ci: 添加文档自动同步至 dae-docs 项目 by @yqlbu in https://github.com/daeuniverse/dae/pull/103
- docs(routing.md): 修订 fwmark 一节的文档 by @mzz2017 in https://github.com/daeuniverse/dae/pull/113

#### Changes

- feat: support iptables tproxy by @mzz2017 in https://github.com/daeuniverse/dae/pull/80
- feat: add uTLS support by @AkinoKaede in https://github.com/daeuniverse/dae/pull/94
- feat: support geosite attr by @mzz2017 in https://github.com/daeuniverse/dae/pull/98
- fix(dns): mismatched qname matching rules by @mzz2017 in https://github.com/daeuniverse/dae/pull/99
- feat(dns): support fixed domain ttl by @mzz2017 in https://github.com/daeuniverse/dae/pull/100
- fix: rand seed for network check by @mzz2017 in https://github.com/daeuniverse/dae/pull/106
- fix(config_parser): potential panic due to out of index by @mzz2017 in https://github.com/daeuniverse/dae/pull/108
- fix(trojan): potential panic due to incorrect n returned by ReadFrom by @mzz2017 in https://github.com/daeuniverse/dae/pull/109

#### Other Changes

- ci: add check-docs workflow by @yqlbu in https://github.com/daeuniverse/dae/pull/93
- refactor: move insert.sh to ./hack/test by @yqlbu in https://github.com/daeuniverse/dae/pull/95
- ci(hack): add config-doc-generator by @yqlbu in https://github.com/daeuniverse/dae/pull/101
- fix(test): domain_matcher/benchmark_test.go @mzz2017 in https://github.com/daeuniverse/dae/pull/107
- ci: docs synchronization by @yqlbu in https://github.com/daeuniverse/dae/pull/103
- docs(routing.md): revise fwmark section by @mzz2017 in https://github.com/daeuniverse/dae/pull/113

#### New Contributors

- @AkinoKaede made their first contribution in https://github.com/daeuniverse/dae/pull/94

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.10...v0.2.0rc1

**Example Config**: https://github.com/daeuniverse/dae/blob/v0.2.0rc1/example.dae

### 0.1.10.p1 (Current)

> Release date: 2023/06/05

#### 功能变更

- fix(trojan): 修复因无效的 trojan 协议控制字段而导致的程序崩溃 by @mzz2017 in https://github.com/daeuniverse/dae/pull/120

#### Changes

- fix(dns): potential panic due to invalid packet control data by accident by @mzz2017 in https://github.com/daeuniverse/dae/pull/120

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.9...v0.1.10.p1

**Example Config**: https://github.com/daeuniverse/dae/blob/v0.1.10.p1/example.dae

### 0.1.10

> Release date: 2023/06/04

#### 功能变更

- feat: 支持 `tcp_check_http_method` by @mzz2017 in https://github.com/daeuniverse/dae/pull/77
- patch: 现在会优先在配置文件同目录搜索 geodata by @mzz2017 in https://github.com/daeuniverse/dae/pull/84
- fix(dns): 修复 0.1.8 版本中 PR #63 导致的 DNS 缓存不会过期的问题 by @mzz2017 in https://github.com/daeuniverse/dae/pull/87
- patch(geodata): 修复由 #84 导致的错误的 geodata 搜索路径 `/etc/dae/dae` by @mzz2017 in https://github.com/daeuniverse/dae/pull/90

#### 其他变更

- chore(Makefile): 添加 export GOOS=linux 以修复在 macos 上的构建 by @mzz2017 in https://github.com/daeuniverse/dae/pull/78
- chore: 添加 editorconfig 文件以美化 github 上对 go 文件的展示 by @yqlbu in https://github.com/daeuniverse/dae/pull/85
- chore: 添加 PR 模板 by @yqlbu in https://github.com/daeuniverse/dae/pull/86

#### Changes

- feat: support `tcp_check_http_method` by @mzz2017 in https://github.com/daeuniverse/dae/pull/77
- patch: search geodata at same dir with config first by @mzz2017 in https://github.com/daeuniverse/dae/pull/84
- fix(dns): cache would never expire caused by #63 by accident by @mzz2017 in https://github.com/daeuniverse/dae/pull/87
- patch(geodata): fix incorrect geodata search path `/etc/dae/dae` caused by #84 by @mzz2017 in https://github.com/daeuniverse/dae/pull/90

#### Other Changes

- chore(Makefile): add export GOOS=linux to build on macos by @mzz2017 in https://github.com/daeuniverse/dae/pull/78
- chore: add editorconfig by @yqlbu in https://github.com/daeuniverse/dae/pull/85
- chore: add pull_request_template by @yqlbu in https://github.com/daeuniverse/dae/pull/86

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.9...v0.1.10

**Example Config**: https://github.com/daeuniverse/dae/blob/v0.1.10/example.dae

### 0.1.9-patch.1

> Release date: 2023/05/14

#### 功能变更

- 修复(dns): 修复 0.1.8 版本中 PR #63 导致的 DNS 缓存不会过期的问题 by @mzz2017 in https://github.com/daeuniverse/dae/pull/87

#### Changes

- fix(dns): cache would never expire caused by #63 by accident by @mzz2017 in https://github.com/daeuniverse/dae/pull/87

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.9...v0.1.9patch1

### 0.1.9

> Release date: 2023/05/09

#### 功能变更

- 修复 trojan UDP 不通的问题 by @mzz2017 in https://github.com/daeuniverse/dae/pull/71
- 修复 `curl http://[ipv6]:port` 不通的问题 by @mzz2017 in https://github.com/daeuniverse/dae/pull/70

#### 其他变更

- 修复 docker 镜像构建的 CI 会在特定名称的分支提交时意外地运行的问题 by @mzz2017 in https://github.com/daeuniverse/dae/pull/72

#### Changes

- fix(trojan): udp problem by @mzz2017 in https://github.com/daeuniverse/dae/pull/71
- fix(sniffing): fail to `curl http://[ipv6]:port` by @mzz2017 in https://github.com/daeuniverse/dae/pull/70

#### Other Changes

- fix(ci): PR runs docker action in some cases by @mzz2017 in https://github.com/daeuniverse/dae/pull/72

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.8...v0.1.9

### 0.1.8 (Current)

> Release date: 2023/04/30

#### 功能变更

- optimize: DNS 缓存空解析和非 A/AAAA 查询，以及 reject 使用 0.0.0.0 和 :: by @mzz2017 in https://github.com/daeuniverse/dae/pull/63
- feat: 支持为 `tcp_check_url` 和 `udp_check_dns` 设定固定 IP 以防止 DNS 污染对 ipv4/ipv6 的支持带来影响 by @mzz2017 in https://github.com/daeuniverse/dae/commit/9493b9a0aa82573fed934bf62cc836f0fe148607

#### 其他变更

- chore: 增加 changelogs by @yqlbu in https://github.com/daeuniverse/dae/pull/55
- chore: 增加 pre-commit 钩子来格式化代码 by @yqlbu in https://github.com/daeuniverse/dae/pull/59
- style: 格式化 golang 代码风格 by @czybjtu in https://github.com/daeuniverse/dae/pull/58
- chore: 增加 issue 模板 by @yqlbu in https://github.com/daeuniverse/dae/pull/62
- chore(codeowner): 更新 ownership by @yqlbu in https://github.com/daeuniverse/dae/pull/64

#### New Contributors

- @czybjtu made their first contribution in https://github.com/daeuniverse/dae/pull/58

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.7...v0.1.8

### 0.1.7

> Release date: 2023/04/16

#### 特性

支持 `global.sniffing_timeout` 来设定嗅探的超时时间，调大这个值对于时延较高的局域网来说较为有用。

#### 修复

1. 修复无法解析小火箭 shadowrocket 的 vmess+ws+tls 分享链接的问题。
2. 修复域名嗅探失败的问题。

#### PR

- chore: fix doamin regex example by @troubadour-hell in https://github.com/daeuniverse/dae/pull/53
- doc: add badges and contribution guide by @yqlbu in https://github.com/daeuniverse/dae/pull/54

#### New Contributors

- @troubadour-hell made their first contribution in https://github.com/daeuniverse/dae/pull/53

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.6...v0.1.7

### 0.1.6

> Release date: 2023/04/09

#### 特性

- 支持在 dns 的 request 路由中使用 reject 出站。
- 支持在 routing 中使用 `must_组名` 的出站，该规则将强制作用于 DNS 请求，直接通过特定组发出，而绕过 dns 模块，提供给有特殊用途的用户使用。
- 支持在 routing 中使用 `must_rules` 的出站，命中该出站的 DNS 请求将绕过 dns 模块，直接进行路由并发出，提供给有特殊用途的用户使用。
- 支持 v2rayN 格式的 vmess 分享格式中的不标准 bool 值解析。
- 支持在 dns 中使用 `ipversion_prefer`，设定当域名是双栈时，只返回 ipv4 还是只返回 ipv6。

#### 修复

- 修复在 dns 的 response 路由中对无序 ip 序列的支持问题。
- 修复 trojan 可能的 panic 问题。
- dns 缓存丢失且 dial_mode 为 domain 时将尝试重路由，以缓解 dns 缓存丢失时无法使用 domain 进行路由的问题。
- 修复部分游戏无法进入的问题，该问题是由于 tcp 建立连接时，dae 总是等待客户端发包，但一些游戏场景中，首包是由服务端 push 的，因此陷入无限等待。

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.5...v0.1.6

### 0.1.5

> Release date: 2023/03/29

#### 更新内容

- 修复 wan_interface 填入 auto 时可能出现的无法启动的问题。
- 修复 https 协议（naiveproxy）的支持问题，新增对 h2 的长连接和多路复用。
- 移除 DNS 抢答检测器，因为它不总是在所有地区都有效，而且在失效时会减慢查询速度。
- 文档（example.dae）：增加通过节点标签精确筛选节点的示例 @yqlbu in https://github.com/daeuniverse/dae/pull/44
- 文档（example.dae）：新增一个 tcp 健康检测 url by @yqlbu in https://github.com/daeuniverse/dae/pull/46

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.4...v0.1.5

### 0.1.4

> Release date: 2023/03/25

#### 更新内容

- domain routing 给出不标准的域名时将忽略而不是报错。
- 将 config 所在目录加入到 geodata 的搜索路径。
- 优化 udp 的内存占用。
- 忽略 sighup 而使用 sigusr2 作为 suspend 的信号。
- 支持自动配置 sysctl 参数。
- 文档: 更新 debian-kernel-upgrade by @yqlbu in https://github.com/daeuniverse/dae/pull/39

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.3...v0.1.4

### 0.1.3

> Release date: 2023/03/24

#### 用户相关

- 新增 amd64_v2_sse 和 amd64_v3_avx 的可执行文件构建，使用更高的版本理论上可提高一定性能（这次 Release 的 CI 失败了，等下次吧） by @MarksonHon in https://github.com/daeuniverse/dae/pull/38
- 支持自动侦测 WAN 接口，在 wan_interface 填入 auto 即可。
- 修复热重载失败时的不正确的回滚行为，以及在一定条件下更改 group 配置时可能无法连接新组的问题。
- 修复在有 MAC 地址路由的情况下 bind to WAN 将导致无网络的问题。
- 修改启动时网络联通性检查使用的链接 https://github.com/daeuniverse/dae/commit/c2e02482d0588823d2a3d9cae6998b9a7a5a1fae 。
- 修复在一定条件下可能的针对 DNS upstream 的域名分流失败的问题。

#### 开发者相关

- 打包了包括 go vendor 和 git submodules 在内的源码并随 releases 发布。
- 增加了 export 命令的描述。

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.2...v0.1.3

### 0.1.2

> Release date: 2023/03/22

1. 优化热重载时的 DNS 缓存行为，解决热重载时 outbound out of range 的问题。
2. 增加高通的 generate_204 作为网络联通性检查的链接，以解决部分用户无法访问`www.msftconnecttest.com`的问题。
3. 支持龙芯 loong64 架构。
4. 修复大并发下可能的崩溃问题。

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.1...v0.1.2

### 0.1.1

> Release date: 2023/03/16

#### What's Changed

- feat: shorten docker command arguments by leveraging CMD by @kunish in https://github.com/daeuniverse/dae/pull/35

#### New Contributors

- @kunish made their first contribution in https://github.com/daeuniverse/dae/pull/35

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.0...v0.1.1

### 0.1.0

> Release date: 2023/03/14

Goose out of shell.
