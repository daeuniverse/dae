# 原生 API

dae 可以提供与 [api-standardize](https://github.com/daeuniverse/api-standardize)
契约兼容的原生 HTTP 控制面。该 listener **默认关闭**。

## 配置

```dae
api {
    enabled: true
    listen: '127.0.0.1:9527'
    secret: 'replace-with-a-long-random-token'
    allow_anonymous_loopback: false
    allow_origins: 'http://localhost:3000'
    allowed_hosts: 'panel.example,panel.example:443'
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

## 端点

当前已实现：

- `GET /api` — discovery
- `GET /api/v1/version`
- `GET /api/v1/capabilities`
- `GET /api/v1/runtime`
- `GET /api/v1/runtime/traffic/history?window_seconds=&max_points=`
- `GET /api/v1/groups`
- `GET /api/v1/groups/{group_id}`
- `GET /api/v1/groups/{group_id}/config`（只读，`ETag` 为配置 revision）
- `PUT /api/v1/groups/{group_id}/selection` — 切换 `select` 组成员，或在自动策略上
  pin 一个成员
- `DELETE /api/v1/groups/{group_id}/selection` — 取消 pin；`select` 组返回
  `409 state_conflict`，`fixed` 返回 `422 unsupported_value`
- `GET /api/v1/nodes?group_id=&limit=&cursor=`
- `GET /api/v1/nodes/{node_id}`
- `POST /api/v1/operations/reload`
- `POST /api/v1/operations/suspend`
- `POST /api/v1/operations/resume`
- `GET /api/v1/operations/{operation_id}`

其他契约资源在实现前返回 `404 capability_not_supported`。已规划但尚未实现：`providers`、
`geodata`、`rules`、`dns/*`、`connections`、`flows`、`events`、`logs`、`probes`、
`runtime/memory*`、`runtime/outbounds`、`datapath`。
`PATCH /api/v1/groups/{group_id}/config`、`POST /api/v1/nodes`、
`DELETE /api/v1/nodes/{node_id}` 始终返回 `404 capability_not_supported`，因为
dae 不通过 API 写入配置（`nodes.can_manage = false`）。

### 组与运行时选择

组 ID 与成员 ID 在 reload 之间保持稳定：`g_` / `n_` 加组名或节点 link 的哈希。成员以
`kind: "node"` 报告。

`policy.kind` 与 dae 策略对应：`select` 为 `selector`，`fixed` 为 `fixed`，`random`
为 `random`，`min` / `min_avg10` / `min_moving_avg` 为 `urltest`。`selector`
接受 `PUT .../selection`；自动策略（`random` 与三个 `min*`）把同样的调用当作运行时
pin（`can_override: true`）；`fixed` 不接受任何运行时选择：

```bash
curl -X PUT -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' \
  -d '{"member_id":"n_18f2c6a4b311","network":"both"}' \
  http://127.0.0.1:9527/api/v1/groups/g_5f2c1d7a8e04/selection
```

`network` 可为 `tcp`、`udp` 或 `both`；TCP 与 UDP 的选择互相独立。`selector` 报告
`source: "runtime"`，自动策略上的 pin 报告 `source: "override"`。两者都只存在内存中：
不会写回配置文件，下一次 reload（或重启）会回到配置的行为。

pin 在该 transport 上优先于自动策略，且与 `selector` 一样忽略探测健康状态；UDP 准入
也不会因为 data-UDP 探测域未就绪而丢弃被 pin 的成员。pin 不改变 kernel 准入：自动组内所有成员都不健康时 kernel 仍会拒绝该组，因此请 pin 一个确认可达的
成员。`DELETE .../selection` 清除 pin，策略重新自动选择；响应里的
`{tcp: null, udp: null}` 表示自动策略没有稳定选择可报告。

`config` 始终返回契约要求的 7 个 key，组未设置时为 `null`；另有 `x-dae` 携带 dae 自己的
`check_addresses`、`tcp_check_http_method`、`udp_check_dns`。

`runtime.health` 按成员与网络域（TCP、DNS-UDP、data-UDP）列出实际探测过的观测，含
`state`、`latency_ms`、`moving_avg_ms`、`avg10_ms`、`observed_at`，以及组排序所用的
`sorting_latency_ms`（`min` 用最近延迟、`min_avg10` 用 10 次平均、`min_moving_avg`
用移动平均、`random` 为 `null`）。从未探测过的网络域直接省略，而不是编造时间戳，因此刚
启动时返回 `[]`。`warmth` 恒为 `unknown`、`ranking` 为 `null`，因为 dae 不跟踪这两项。

### 节点

`GET /api/v1/nodes` 列出本 generation 管理的全部 dialer，包括当前没有任何组选中的节点；
`group_id` 可把列表限制到某个组的成员（未知组返回 `404 resource_not_found`）。ID 与组成员
使用同一套稳定的 `n_` 标识，只要节点的分享链接不变，跨 reload 保持稳定。

`limit` 为 1–1000（默认 100）。`cursor` 不透明且绑定到某一个 generation：reload 之后复用
旧 cursor 返回 `410 snapshot_expired`，表示需要重新从头遍历。最后一页的
`next_cursor` 为 `null`。

两个订阅携带同一个分享链接时是同一个节点（ID 由链接派生），因此列表只报告一次，
并把组成员关系与健康观测合并；组同样把它当作一个成员。

`health` 与组报告的是同一套投影，按 transport / purpose / IP 版本区分。
`subscription_tag` 为节点来源订阅，内联节点为 `null`；`provider_id` 恒为 `null`，因为 dae
没有 providers 资源。节点管理（`POST`、`DELETE`）返回
`404 capability_not_supported`。

### 流量历史

`GET /api/v1/runtime/traffic/history` 返回记录器采样，按时间从旧到新。`window_seconds`
默认 3600（上限 3600），`max_points` 默认 180（上限 180）；超范围或非数字返回
`400 invalid_request`，不会静默截断。`sampled_every_seconds` 是返回采样点的实际间隔，
为满足 `max_points` 做抽稀时会变大。抽稀是"每 N 个取一个"并原样保留时间戳与速率，
不做平均或取最大值，因此返回序列不会出现记录器没测到的峰值。`connections` 为 `null`。

### 异步操作

`reload`、`suspend`、`resume` 是异步操作：返回 `202` 并带 `Location` 与
`Retry-After: 1`，通过 `GET /api/v1/operations/{operation_id}` 轮询 `queued` /
`running` / `succeeded` / `failed`。已有 reload 进行中时返回 `409 state_conflict`，
其 `details.operation_id` 指向被拒绝的记录。`Idempotency-Key` 对相同请求重放原始
`202` body，同一 key 用于不同操作时返回 `409 idempotency_conflict`。记录在内存中保留
3600 秒；未完成的操作不会被淘汰。

配置了 `ui` 时，`/ui/` 提供前端，其余非 `/api` 路径都会重定向到那里，因此只有 `/api` 与
`/api/v1/...` 参与认证。

`GET /api/v1/version` 报告的版本与 `dae -v` 完全一致：优先使用构建注入的版本；直接
`go build`/`go install` 时回退到模块或 VCS 版本。`build` 携带来自 Go 构建信息的
`revision`、`target`、`built_at`，构建未提供时对应字段为 `null`。

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

## 日志

API 写入 dae 的常规日志：

- **每条请求**：`debug` 级，字段 `method`、`route`、`status`、`elapsed_ms`、
  `request_id`、`remote_ip`、`bytes`。面板通常每几秒轮询一次，因此默认 `info` 级别下不打
  印，避免刷屏。
- **拒绝与失败**：立即记录，`4xx` 用 `info`、`5xx` 用 `error`，并带上契约的
  `error_code`（如 `authentication_required`、`permission_denied`、
  `capability_not_supported`）。
- **滚动汇总**：listener 有流量时每 60 秒输出一行 `Native API traffic`，含 `served`、
  `refused`、`window_seconds`。
- listener 启动与停止。

日志不记录请求头和查询串，因此 `Authorization` token 与配置里的 `secret` 不会落盘；路由
按模板记录，随机探测路径不会撑爆日志。

## reload 行为

`api` 的所有字段都是 restart-required。reload 检测到变化时会拒绝或保留旧 listener
并打印 warning，不会部分重建 listener。

## 示例

```bash
curl http://127.0.0.1:9527/api
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9527/api/v1/runtime
```
