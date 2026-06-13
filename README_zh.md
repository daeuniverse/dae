# dae

<img src="https://github.com/daeuniverse/dae/blob/main/logo.png" border="0" width="25%">

<p align="left">
    <img src="https://github.com/daeuniverse/dae/actions/workflows/build.yml/badge.svg" alt="Build"/>
    <img src="https://custom-icon-badges.herokuapp.com/github/license/daeuniverse/dae?logo=law&color=orange" alt="License"/>
    <img src="https://custom-icon-badges.herokuapp.com/github/v/release/daeuniverse/dae?logo=rocket" alt="version">
    <img src="https://custom-icon-badges.herokuapp.com/github/issues-pr-closed/daeuniverse/dae?color=purple&logo=git-pull-request&logoColor=white"/>
    <img src="https://custom-icon-badges.herokuapp.com/github/last-commit/daeuniverse/dae?logo=history&logoColor=white" alt="lastcommit"/>
</p>

> **这是一个增强版 Fork**，为 `fixed` 拨号模式增加了完整的灾备能力。
> 预编译二进制请见 [Releases](https://github.com/itoywh/dae/releases)。

## Fork 增强内容

### 1. fixed_fallback — 灾备拨号策略

原生 `fixed` 模式有一个致命缺陷：**如果固定节点挂了，流量就直接断了**。没有故障转移机制 — 这是一个单点故障。

本 Fork 引入 `fixed_fallback`，将 `fixed` 从脆弱的单点模式升级为 **生产级高可用策略**，具备完整的灾备语义。

---

#### 快速上手

```ini
# 在 dae 配置文件中 (如 /etc/dae/config.dae):
[group]
my_group {
    policy: fixed_fallback(1, 5s, 3)
}

[global]
check_tolerance: 60ms
```

含义：优先使用组内第 2 个节点（索引 1，从 0 开始）。如果连接失败，每次超时 5 秒、最多重试 3 次 → 全部失败后自动切到最佳存活节点。固定节点恢复后自动切回。60ms 容差防止来回抖动。

---

#### 参数详解

```
fixed_fallback(<索引>, <超时>, <重试次数>[, <fallback策略>])
```

| # | 参数 | 必填 | 说明 | 示例 |
|---|------|------|------|------|
| 1 | **`索引`** | ✅ | 固定节点在 group 节点列表中的 0-based 索引。第一个节点是 `0`，第二个是 `1`，以此类推。超出范围则直接走 fallback 池。 | `1` → 用第 2 个节点 |
| 2 | **`超时`** | ✅ | 每次连接的超时时间。支持单位后缀：`ms`（毫秒）、`s`（秒）、`m`（分钟）。不带后缀视为秒（向后兼容）。 | `5s`、`500ms`、`2m`、`10`（即 10 秒） |
| 3 | **`重试次数`** | ✅ | 宣告固定节点死亡并触发 fallback 之前的最大重试次数。耗尽后会输出 WARN 级别日志。 | `3` → 重试 3 次 |
| 4 | **`fallback策略`** | ❌ | 固定节点宕机后选择备用节点的策略。省略则默认使用 `min_moving_avg`。 | 见下表面 |

##### Fallback 策略选项

| 策略 | 行为 | 适用场景 |
|------|------|----------|
| `min_moving_avg` ⭐ *(默认)* | 选择移动平均延迟最低的节点。配合 `check_tolerance` 防抖动。 | 通用场景 — 延迟敏感流量 |
| `min_last_latency` | 选择最近一次实测延迟最低的节点。 | 网络条件快速变化的环境 |
| `random` | 从存活的 fallback 节点池中随机选一个。 | 负载均衡 — 希望分散流量到备用节点池 |

##### check_tolerance 与 fixed_fallback 的配合

`check_tolerance` 配置项（位于 `[global]` 下）与 fallback 策略协同工作，防止节点来回切换（抖动）。当固定节点恢复后，如果其延迟与当前 fallback 节点相比差距在 `check_tolerance` 范围内，dae 不会立即切回 — 避免了流量在两个节点间振荡。

```ini
[global]
check_tolerance: 60ms   # 仅当固定节点延迟比 fallback 节点好 ≥60ms 时才切回
```

---

#### 工作原理

```
┌─ 正常工作流程 ─────────────────────────────────────────────┐
│                                                             │
│  fixed_fallback(1, 5s, 3, min_moving_avg)                  │
│                                                             │
│  1. 尝试连接固定节点（索引 1 = 第 2 个节点）                 │
│     ├─ 存活？→ 使用它。完成 ✅                               │
│     └─ 宕机/超时？→ 重试（最多 3 次）                       │
│                                                             │
│  2. 3 次重试全部耗尽？                                       │
│     └─ WARN 日志: "fixed dialer retries exhausted (3/3)"   │
│        → 按 min_moving_avg 从存活节点中选择最优              │
│        → INFO 日志: "falling back to <node>"               │
│                                                             │
│  3. Connectivity Checker 周期性探测固定节点                  │
│     └─ 固定节点恢复了？                                      │
│        ├─ 延迟在 check_tolerance 范围内？→ 保持 fallback     │
│        └─ 延迟明显更好？→ 自动切回 🔄                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

#### 配置示例

**示例 A：简单灾备** — 优先用 s4，不可用时切到其他存活节点：
```ini
[group]
my_group {
    nodes: s4, s2, s5
    policy: fixed_fallback(0, 5s, 3)
}
```

**示例 B：随机 fallback（负载均衡）** — 把 fallback 流量均匀分散到各备用节点：
```ini
[group]
my_group {
    nodes: s4, s2, s5
    policy: fixed_fallback(0, 3s, 2, random)
}
```

**示例 C：配合 check_tolerance** — 防止延迟接近时来回切换：
```ini
[global]
check_tolerance: 80ms

[group]
my_group {
    nodes: s_hk, s_jp, s_sg
    policy: fixed_fallback(0, 5s, 3)        # min_moving_avg（默认）
}
```

**示例 D：激进超时** — 快失败，只重试一次：
```ini
policy: fixed_fallback(0, 500ms, 1, min_last_latency)
```

---

#### 兼容性

- **向后兼容**：现有的 `fixed_fallback(1, 5s, 3)` 配置无需修改即可继续使用
- **超时单位向后兼容**：`fixed_fallback(1, 5, 3)`（不带后缀）仍然可用 — 视为秒
- **与所有现有策略共存**：`fixed_fallback` 是新增策略，其他策略（`random`、`min_moving_avg` 等）保持不变

---

### 2. 日志格式优化

日志时间戳改为人类可读格式，启用 `ForceFormatting`：

```
修改前：INFO selected dialer: s4 ...
修改后：[2026-06-13 15:04:05] INFO selected dialer: s4 ...
```

`[年-月-日 时:分:秒]` 前缀方便阅读，也便于用标准工具（如 `grep`、`awk`、日志查看器）解析。

---

### 上游 PR

- [PR #1009](https://github.com/daeuniverse/dae/pull/1009) — fixed_fallback 灾备增强
- [PR #1010](https://github.com/daeuniverse/dae/pull/1010) — 日志时间戳格式优化

---

**_dae_**，意为 goose（鹅），是一款高性能透明代理解决方案。

为了尽可能地提升流量分流的性能，dae 在 Linux 内核中使用 eBPF 实现了透明代理和流量分流套件。因此，dae 可以让直连流量绕过代理应用的转发，实现真正的直接通过。凭借这一卓越特性，直连流量几乎没有性能损失和额外的资源消耗。

作为 [v2rayA](https://github.com/v2rayA/v2rayA) 的后继者，dae 放弃了 v2ray-core，以更自由地满足用户需求。

## 特性

- [x] 实现 `Real Direct` 流量分流（需开启 ipforward）以达到[高性能](https://docs.google.com/spreadsheets/d/1UaWU6nNho7edBNjNqC8dfGXLlW0-cm84MM7sH6Gp7UE/edit?usp=sharing)
- [x] 支持按本机进程名分流流量
- [x] 支持按 LAN 内 MAC 地址分流流量
- [x] 支持反向匹配规则分流流量
- [x] 支持按策略自动切换节点。即自动测试独立的 TCP/UDP/IPv4/IPv6 延迟，然后根据用户定义的策略为相应流量使用最佳节点
- [x] 支持高级 DNS 解析过程
- [x] 支持 shadowsocks、trojan(-go) 和 socks5 的 full-cone NAT（未经测试）
- [x] 支持多种主流代理协议，详见 [proxy-protocols.md](./docs/en/proxy-protocols.md)

## 快速开始

请参考 [快速开始指南](./docs/en/README.md) 立即开始使用 `dae`！

## 注意事项

1. 如果你在公网（如 VPS）的同一台机器上同时部署 dae 和 shadowsocks 服务端（或任何 UDP 服务），别忘了为你的 UDP 服务端口添加 `l4proto(udp) && sport(你的服务端口) -> must_direct` 规则。因为 UDP 状态难以维护，所有出站 UDP 包都有可能被代理（取决于你的路由规则），包括发给客户端的流量。这不是我们期望的行为。`must_direct` 会让该端口的所有流量（包括 DNS 流量）直连。
2. 如果中国大陆用户访问某些国内网站时发现首次加载时间很长，请检查是否在 DNS 路由中使用了国外 DNS 处理某些国内域名。这个问题有时很难发现。例如，`ocsp.digicert.cn` 意外地被包含在 `geosite:geolocation-!cn` 中，这会导致某些 TLS 握手耗时很长。在 DNS 路由中使用此类域名集合时请格外小心。

## 工作原理

详见 [How it works](./docs/en/how-it-works.md)。

## TODO

- [ ] 自动检查 DNS 上游和源循环（上游是否也是我们的客户端）并提醒用户添加 sip 规则
- [ ] MACv2 扩展提取
- [ ] 日志输出到用户空间
- [ ] 面向协议的节点特性检测（或过滤），如 full-cone（特别是 VMess 和 VLESS）
- [ ] 添加快速开始指南
- [ ] ...

## 贡献者

特别感谢所有[贡献者](https://github.com/daeuniverse/dae/graphs/contributors)。如果你想贡献代码，请参阅[说明](./docs/en/development/contribute.md)。同时建议遵循 [commit-msg-guide](./docs/en/development/commit-msg-guide.md)。

## 许可证

[AGPL-3.0 (C) daeuniverse](https://github.com/daeuniverse/dae/blob/main/LICENSE)

## 星标历史

[![Stargazers over time](https://starchart.cc/daeuniverse/dae.svg)](https://starchart.cc/daeuniverse/dae)
