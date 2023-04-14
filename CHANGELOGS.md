# Changelogs

Also seen in [GitHub Releases](https://github.com/daeuniverse/dae/releases)

HTML version available at https://dae.v2raya.org/docs/changelogs

## Query history releases

```bash
curl --silent "https://api.github.com/repos/daeuniverse/dae/releases" | jq -r '.[] | {tag_name,created_at,prerelease}'
```

## Releases

- [0.1.7 (Pre-release)](#0.1.7)
- [0.1.6](#0.1.6)
- [0.1.5 (Current)](#0.1.5)
- [0.1.4](#0.1.4)
- [0.1.3](#0.1.3)
- [0.1.2](#0.1.2)
- [0.1.1](#0.1.1)
- [0.1.0](#0.1.0)

### 0.1.7 (Pre-release)

> Release date: 2023/04/12

## 特性

支持 `global.sniffing_timeout` 来设定嗅探的超时时间，调大这个值对于时延较高的局域网来说较为有用。

## 修复

1. 修复无法解析小火箭 shadowrocket 的 vmess+ws+tls 分享链接的问题。
2. 修复域名嗅探失败的问题。

## PR

- chore: fix doamin regex example by @troubadour-hell in https://github.com/daeuniverse/dae/pull/53
- doc: add badges and contribution guide by @yqlbu in https://github.com/daeuniverse/dae/pull/54

## New Contributors

- @troubadour-hell made their first contribution in https://github.com/daeuniverse/dae/pull/53

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.6...v0.1.7

### 0.1.6

> Release date: 2023/04/09

### 特性

- 支持在 dns 的 request 路由中使用 reject 出站。
- 支持在 routing 中使用 `must_组名` 的出站，该规则将强制作用于 DNS 请求，直接通过特定组发出，而绕过 dns 模块，提供给有特殊用途的用户使用。
- 支持在 routing 中使用 `must_rules` 的出站，命中该出站的 DNS 请求将绕过 dns 模块，直接进行路由并发出，提供给有特殊用途的用户使用。
- 支持 v2rayN 格式的 vmess 分享格式中的不标准 bool 值解析。
- 支持在 dns 中使用 `ipversion_prefer`，设定当域名是双栈时，只返回 ipv4 还是只返回 ipv6。

### 修复

- 修复在 dns 的 response 路由中对无序 ip 序列的支持问题。
- 修复 trojan 可能的 panic 问题。
- dns 缓存丢失且 dial_mode 为 domain 时将尝试重路由，以缓解 dns 缓存丢失时无法使用 domain 进行路由的问题。
- 修复部分游戏无法进入的问题，该问题是由于 tcp 建立连接时，dae 总是等待客户端发包，但一些游戏场景中，首包是由服务端 push 的，因此陷入无限等待。

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.5...v0.1.6

### 0.1.5 (Latest)

> Release date: 2023/03/29

- 修复 wan_interface 填入 auto 时可能出现的无法启动的问题。
- 修复 https 协议（naiveproxy）的支持问题，新增对 h2 的长连接和多路复用。
- 移除 DNS 抢答检测器，因为它不总是在所有地区都有效，而且在失效时会减慢查询速度。
- 文档（example.dae）：增加通过节点标签精确筛选节点的示例 @yqlbu in https://github.com/daeuniverse/dae/pull/44
- 文档（example.dae）：新增一个 tcp 健康检测 url by @yqlbu in https://github.com/daeuniverse/dae/pull/46

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.4...v0.1.5

### 0.1.4

> Release date: 2023/03/25

## 更新内容

- domain routing 给出不标准的域名时将忽略而不是报错。
- 将 config 所在目录加入到 geodata 的搜索路径。
- 优化 udp 的内存占用。
- 忽略 sighup 而使用 sigusr2 作为 suspend 的信号。
- 支持自动配置 sysctl 参数。
- 文档: 更新 debian-kernel-upgrade by @yqlbu in https://github.com/daeuniverse/dae/pull/39

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.3...v0.1.4

### 0.1.3

> Release date: 2023/03/24

## 用户相关

- 新增 amd64_v2_sse 和 amd64_v3_avx 的可执行文件构建，使用更高的版本理论上可提高一定性能（这次 Release 的 CI 失败了，等下次吧） by @MarksonHon in https://github.com/daeuniverse/dae/pull/38
- 支持自动侦测 WAN 接口，在 wan_interface 填入 auto 即可。
- 修复热重载失败时的不正确的回滚行为，以及在一定条件下更改 group 配置时可能无法连接新组的问题。
- 修复在有 MAC 地址路由的情况下 bind to WAN 将导致无网络的问题。
- 修改启动时网络联通性检查使用的链接 https://github.com/daeuniverse/dae/commit/c2e02482d0588823d2a3d9cae6998b9a7a5a1fae 。
- 修复在一定条件下可能的针对 DNS upstream 的域名分流失败的问题。

## 开发者相关

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

## What's Changed

- feat: shorten docker command arguments by leveraging CMD by @kunish in https://github.com/daeuniverse/dae/pull/35

## New Contributors

- @kunish made their first contribution in https://github.com/daeuniverse/dae/pull/35

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.0...v0.1.1

### 0.1.0

> Release date: 2023/03/14

Goose out of shell.
