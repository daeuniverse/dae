# 原生 API

dae 可以提供与 [api-standardize](https://github.com/daeuniverse/api-standardize)
契约兼容的原生 HTTP 控制面。该 listener **默认关闭**。

本页讲 listener 的配置与部署，以及通过 API 写配置所需的目录规范；端点行为与资源契约见
[development/api.md](../development/api.md)。

## 配置

```dae
api {
    enabled: true
    listen: '127.0.0.1:9527'
    secret: 'replace-with-a-long-random-token'
    allow_anonymous_loopback: false
    allow_origins: 'http://localhost:3000'
    allowed_hosts: 'panel.example,panel.example:443'
    config_write: false
    disable_connection_bytes: false
    direct_stats: false
}
```

| 字段 | 默认值 | 说明 |
|---|---|---|
| `enabled` | `false` | 是否启动原生 listener。 |
| `listen` | `127.0.0.1:9527` | 数字 IP + 端口。不接受 hostname 或 `:port` 简写。 |
| `secret` | 空 | 非空表示 token mode；所有非 discovery 请求必须带 `Authorization: Bearer <secret>`。 |
| `allow_anonymous_loopback` | `false` | 仅当 `secret` 为空且 listener 实际绑定 loopback 时，允许无凭证访问。 |
| `allow_origins` | 空 | 允许跨域访问的精确 HTTP(S) origin。 |
| `allowed_hosts` | 空 | 额外接受的 Host authority；省略端口按 80 处理。 |
| `ui` | 空 | 存放已构建前端的绝对目录，在 `/ui/` 下无凭证访问；非 `/api` 路径会重定向到这里；留空表示不托管前端。 |
| `config_write` | `false` | 是否允许通过 API 替换配置源。需要同时设置非空 `secret`，且配置目录符合下面的规范结构。 |
| `disable_connection_bytes` | `false` | 不下发每条连接的累计上/下行字节（`upload_bytes` / `download_bytes`）。详见下面的流量统计口径。 |
| `direct_stats` | `false` | 在 dae 已绑定的 WAN/LAN 接口上挂只读 eBPF 观测钩子，统计直连流量。仅当 `enabled` 为 true 时生效；详见下面的流量统计口径。 |

## 通过 API 编辑配置

`config_write: true` 只是开关；真正能否写入还取决于**配置目录的结构**。dae 不做行级编辑，
只接受「整份替换某个源文件」，因此要求配置按固定规范拆分好：

```sh
# tree /etc/dae
/etc/dae
├── config.dae          # 入口：只有一个 include 块
├── api.dae             # api 块；对 API 完全隐藏，只能人工编辑
└── config.d
    ├── global.dae
    ├── subscription.dae
    ├── node.dae
    ├── group.dae
    ├── routing.dae
    └── dns.dae
```

```dae
# config.dae
include {
    config.d/*.dae
    api.dae
}
```

下表条件全部满足才可写，任一不满足即整体禁用——不会出现「一个文件改成功、另一个失败」的状态：

| # | 条件 |
|---|---|
| 1 | 入口文件名必须是 `config.dae`。 |
| 2 | 入口只允许一个 `include` 块，且不得含其它 section。 |
| 3 | `include` 展开集合必须正好是 `config.d/*.dae` 与 `api.dae`，多一个少一个都不行。 |
| 4 | `api.dae` 必须存在；`config.d/` 必须包含上面六个模块文件。 |
| 5 | `config.d/*.dae` 内不得再出现 `include`。 |
| 6 | 每个 section 只能来自一个文件，例如 `dns` 只能写在 `dns.dae`。 |
| 7 | 配置文件不能被同组写入或执行，也不能被其他用户以任何方式访问；建议 `0640` 或 `0600`。 |
| 8 | `config.d/` 必须可写（写入要落 `.bak` 与临时文件）。 |

满足条件后，每一类改动都是替换对应模块文件：改节点替换 `node.dae`，改分组替换
`group.dae`，改路由替换 `routing.dae`，改 DNS 替换 `dns.dae`，改订阅替换
`subscription.dae`，以此类推。不拆分、或只拆一部分的配置，无法通过 API 编辑。

不满足时，写请求返回 `403 permission_denied`，原因放在 `details.reason`，也会出现在
`GET /api/v1/capabilities` 的 `resources.config.x-dae.layout.reason` 中（`writes_disabled`
或 `layout_unmanaged`），同处的 `layout.kind` 则为 `managed` 或 `unmanaged`。

补充约束：

- `api.dae` 对 API 完全隐藏：不出现在源列表里，其 ID 一律返回 `404`。因此**改监听地址、
  端口或 secret 只能人工改文件并重启**。
- `config.dae` 本身只读（`entry_source`），替换时不得改动 `api` 块。
- 写入前会跑与 `dae validate -c` 相同的完整校验；不通过的候选返回 `422` 并附行号，磁盘
  不会变动。

## 流量统计口径

`GET /api/v1/connections` 的 `upload_bytes` / `download_bytes` 只对 dae 在用户态转发并计数
的 TCP 流有值：UDP 流与内核直连（eBPF TCP direct）的流量都不在其中。因此按来源设备或
目标域名聚合出的「流量排行」只能覆盖链路的一部分，dae 无法给出准确的设备级总量。

不希望下发这个不完整的总量时，设置：

```dae
api {
    enabled: true
    listen: '127.0.0.1:9527'
    secret: 'replace-with-a-long-random-token'
    disable_connection_bytes: true
}
```

此时 `upload_bytes` 与 `download_bytes` 恒为 `null`，连接列表的其余字段（来源、目标、
域名、出站、链路）不受影响。

### 直连流量

dae 直连转发的流量不经过 userspace relay，连接计数器看不到它。设置
`direct_stats: true` 后，dae 会在**自己已经绑定的** WAN/LAN 接口上、紧挨 tproxy 的位置
挂一个纯观测 TC 程序。绑定的是桥时会展开到成员口，netlink 监听器在成员加入/离开时增删
观测器；程序不改 mark、不改转发判决。优先使用 TCX，内核不支持时回退 classic TC filter，
后者需要 clsact qdisc，且可能受接口已有 filter 优先级影响。

```dae
api {
    enabled: true
    listen: '127.0.0.1:9527'
    secret: 'replace-with-a-long-random-token'
    direct_stats: true
}
```

之后 `GET /api/v1/runtime/direct-stats` 会返回累计的 `up_bytes`、`up_packets`、
`down_bytes` 与 `down_packets`，以及 `enabled`、`attached`、`counter_since`、
`last_error`。`enabled` 是生效开关，`attached` 表示钩子是否真正挂上；`up_packets` /
`down_packets` 是 **skb 计数**，GSO/GRO 下会低于线缆包数。数字是链路字节而不是 payload
字节，且只是下界：观测钩子在 tproxy 之前运行，所以每条流的第一个包（以及重启前就存在的
流）不会被统计，非 TCP/UDP 流量也不计，缺失 conn_state 的直通流也无法统计。转发回包在
LAN egress（DNAT 之后）计数，因此 MASQUERADE 网关也能统计 LAN 客户端下载；双角色接口仍
保留该限制。钩子先于 tproxy 运行，这些接口上的每个包（包括代理流量）都要付一两次 map
查找的成本；`api.direct_stats` 与 `api` 其余字段一样是 restart-required。

观测计数同时会并入 `GET /api/v1/runtime/outbounds` 的内置 `direct` 行，因此只读该资源的
既有面板（例如 doona 的活动页）无需认识本端点即可看到直连流量。该行此时是混合口径：
内核直连的链路字节加上 relay 统计到的 `must_direct` payload 字节。流量曲线本身仍只含
userspace 可见流量，因为 `runtime.traffic` 与其历史序列没有改变。

## 认证

二选一：

- **Token mode**：设置非空 `secret`。除 `GET /api`（discovery）外，所有请求都必须带
  `Authorization: Bearer <secret>`。
- **匿名 loopback**：`secret` 留空，设置 `allow_anonymous_loopback: true`，并绑定
  loopback 地址。

启用的 listener 如果两种模式都不满足，会校验失败。非 loopback listener 必须设置
`secret`，不能用 `allow_anonymous_loopback` 替代。

按契约实现的浏览器前端（例如 doona）依据 public discovery 的 `auth.mode` 决定登录方式，
而该字段没有“无需认证”这个取值。因此在匿名 loopback 模式下前端仍会要求填写 token：随便
填一个占位值即可。`secret` 为空时，listener 对非 discovery 请求不校验 `Authorization`，
loopback 调用方本来就会被放行。

建议使用至少 16 字节的不可预测 token。`secret` 必须是可见 ASCII，且不能包含空白或
逗号。API 不会返回 secret，日志也不会记录 secret。

`GET /api` 在任何模式下都是公开的：无凭证返回 public discovery view，带有效 token
返回 full view。token mode 下，`/api/v1/version` 和 `/api/v1/capabilities` 同样需要
token。

### 本机免 token

```dae
api {
    enabled: true
    listen: '127.0.0.1:9527'
    allow_anonymous_loopback: true
}
```

`secret` 留空且 listener 绑定 loopback 时，本机请求完全不需要 `Authorization`。契约只
允许在显式 secretless 的 listener 上匿名访问，因此还要对其他主机提供服务时就必须设置
`secret`，此后包括 loopback 在内的所有请求都要带 token。

## TLS

dae 提供 plain HTTP，不负责 TLS 终止。监听非 loopback 地址时，应在受信任的反向代理
处终止 TLS，不要把 listener 直接暴露到不可信网络。dae 会对非 loopback listener 打印
启动 warning；TLS 是部署要求，不是会拒绝 listener 的配置校验项。

## Host 与 Origin 校验

- `Host` 必须匹配配置的监听 authority。loopback listener 额外接受 `localhost`、
  `127.0.0.1`、`[::1]` 及同一端口。wildcard bind 接受 IP-literal Host 和
  `localhost`；DNS 名称需要通过 `allowed_hosts` 显式允许。
- 跨域浏览器访问需要精确匹配 `allow_origins`。
- secretless loopback listener 会拒绝 `Sec-Fetch-Site: cross-site` 请求。
- 不信任 forwarded headers 作为授权依据。

## 自托管前端

把 `ui` 指向存放已构建前端的绝对目录，dae 就在 `<listen>/ui/` 下提供它：

```dae
api {
    enabled: true
    listen: '127.0.0.1:9527'
    secret: 'replace-with-a-long-random-token'
    ui: '/usr/share/doona'
}
```

- 只有 `/api` 与 `/api/v1/...` 是 API 路由，按配置进行认证；其余路径都视为页面访问：
  `/`、`/ui` 以及其他任何路径都重定向到 `/ui/`，因此深链或拼错的路径不会返回认证错误。
- 只提供该目录内的文件；不开启目录列表，缺失的资源（如 `/ui/assets/app.js`）返回真正的
  `404`，不会退化成 HTML。
- 无扩展名的未命中会回退到 `index.html`，因此前端路由（hash 或 history）可正常工作。
- `assets/` 下的内容按 immutable 缓存一年，其余文件用 `no-cache`。
- 静态文件是公开的：浏览器无法给 `<script src>` 附带 Bearer token。前端发出的每个 API
  请求仍然需要 token，上面的 Host/Origin 校验同样作用于 UI。
- 路径必须是绝对路径。目录不存在或缺 `index.html` **不会**导致 dae 退出：启动时打一条
  warning，`/ui/` 在目录可用前返回 `404`，避免前端问题把代理拖垮。修改 `ui` 仍需重启，
  和 `api` 其他字段一致。
- 按本契约构建的前端（例如 [doona](https://github.com/Zakkaus/doona)）从 `/ui/` 提供时
  会把自己所在的 origin 当作后端，因此只需要填一次 token。

## 节点与订阅

启用配置写入后，面板可以直接增删**内联节点**、手动刷新订阅：

- 内联节点只写入 `config.d/node.dae` 的 `node` 段；写入前走与 `dae validate -c`
  相同的校验，并保留 `<文件>.bak`。
- **订阅拉取的节点是只读的**：它们由订阅管理，只能通过刷新或删除该订阅才能变更，删除接口对
  它们返回 `404 capability_not_supported`。
- **节点名全局唯一**：新建时只要任意来源（内联或订阅）已用该名字就返回 `409 state_conflict`。
- 分享链接必须能被引擎解析（`vless` / `vmess` / `trojan` / `ss` / `ssr` / `socks` / `http` /
  `hysteria2` / `tuic` / `juicity` / `anytls` / `naive`），且带主机与端口；否则返回 `422`。
- 手动刷新订阅（`POST /api/v1/providers/{id}/refresh`）会重新拉取并 reload；拉取失败时
  保留上一次成功加载的节点。

## reload 行为

`api` 的所有字段都是 restart-required。reload 检测到变化时会拒绝或保留旧 listener
并打印 warning，不会部分重建 listener。

## 示例

```bash
curl http://127.0.0.1:9527/api
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9527/api/v1/runtime
```
