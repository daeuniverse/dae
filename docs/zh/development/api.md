# 原生 API 参考

listener 的配置、认证、TLS、Host/Origin 校验与自托管前端见
[configuration/api.md](../configuration/api.md)。本页记录 dae 实现的端点与资源契约。

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
- `GET /api/v1/runtime/outbounds` — 按出站统计，reload 后继续累计
- `GET /api/v1/runtime/memory` — 进程、cgroup v2 与 eBPF 内存
- `GET /api/v1/runtime/memory/history?window_seconds=&max_points=`
- `GET /api/v1/datapath` — eBPF 挂载点、routing generation 与 map 占用
- `GET /api/v1/nodes?group_id=&limit=&cursor=`
- `GET /api/v1/nodes/{node_id}`
- `POST /api/v1/operations/reload`
- `POST /api/v1/operations/suspend`
- `POST /api/v1/operations/resume`
- `GET /api/v1/operations/{operation_id}`
- `GET /api/v1/rules` — 当前 generation 的配置态路由规则
- `GET /api/v1/providers`、`GET /api/v1/providers/{provider_id}`
- `GET /api/v1/geodata` — geoip/geosite 资源指纹
- `GET /api/v1/dns/cache`、`DELETE /api/v1/dns/cache?name=`、
  `DELETE /api/v1/dns/cache/{entry_id}`、`POST /api/v1/dns/cache/flush`
- `GET /api/v1/dns/log`、`GET /api/v1/dns/rules`、`POST /api/v1/dns/query`
- `GET /api/v1/connections`、`DELETE /api/v1/connections/{connection_id}`、
  `DELETE /api/v1/connections?all=true`
- `GET /api/v1/flows`、`GET /api/v1/flows/{flow_id}`
- `GET /api/v1/events`、`GET /api/v1/logs` — SSE 事件流
- `POST /api/v1/probes` — 启动节点/组探测，通过
  `GET /api/v1/operations/{operation_id}` 轮询结果

`POST /api/v1/providers`（创建 inline provider）、
`DELETE /api/v1/providers/{provider_id}`、
`POST /api/v1/providers/{provider_id}/refresh`、`POST /api/v1/geodata/update`
返回 `404 capability_not_supported`，与 `providers.can_refresh`、
`providers.can_manage`、`geodata.can_update` 恒为 `false` 一致：dae 不通过 API 写配置
或重新下载资源。`PATCH /api/v1/groups/{group_id}/config`、`POST /api/v1/nodes`、
`DELETE /api/v1/nodes/{node_id}` 出于同样原因返回该错误码
（`nodes.can_manage = false`）。

`/api/v1/config*`、`/api/v1/runtime/settings`、`/api/v1/routing/trace`、
`/api/v1/auth*` 仍未实现，因此需要就地编辑配置的前端页面（例如 lite 版 doona 的路由与
DNS 编辑页）无法对 dae 使用；这里的规则与 DNS 规则是只读视图。

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
成员。`DELETE .../selection` 清除 pin，策略重新自动选择；此时响应报告策略当前选中的
成员，`source: "runtime"`——自动组总会报告它实际拨号的成员——只有 `random` 例外，
它每条连接都重新随机，因此为 `null`。

`config` 始终返回契约要求的 7 个 key，组未设置时为 `null`；另有 `x-dae` 携带 dae 自己的
`check_addresses`、`tcp_check_http_method`、`udp_check_dns`。

`runtime.health` 按成员与网络 key（TCP、DNS-UDP、data-UDP，各自再分 IP 版本）列出观测，
含 `state`、`latency_ms`、`moving_avg_ms`、`avg10_ms`、`observed_at`。`purpose`
表示这段延迟**用于什么流量**，而不是由哪个探针产生：TCP 与 data-UDP 为 `data`，
DNS 为 `dns`。

`sorting_latency_ms` 是引擎真正用于排序的值：策略指标加上恢复惩罚与组的 `add_latency`
偏移，因此可能与旁边的指标字段不同。`ranking` 解释这个分数：`metric`、`score`、
`group_offset_ms`、`recovery_penalty_ms`、`reason`，以及 1 起的 `rank` 和相对同一
key 最优成员的 `delta_to_best_ms`。`rank` 是瞬时排名，而组的选择带有
`check_tolerance` 滞回，两者按设计可能指向不同成员。data-UDP 没有自己的探针：引擎借用
同一 dialer 的 DNS 样本来排序，本投影按同样规则镜像，而不是丢掉该 key。从未探测过的
网络域直接省略，而不是编造时间戳，因此刚启动时返回 `[]`。`warmth` 恒为 `unknown`，
因为 dae 不跟踪冷热。

### 节点

`GET /api/v1/nodes` 列出本 generation 管理的全部 dialer，包括当前没有任何组选中的节点；
`group_id` 可把列表限制到某个组的成员（未知组返回 `404 resource_not_found`）。ID 与组成员
使用同一套稳定的 `n_` 标识，只要节点的分享链接不变，跨 reload 保持稳定。

`limit` 为 1–1000（默认 100）。`cursor` 不透明且绑定到某一个 generation：reload 之后复用
旧 cursor 返回 `410 snapshot_expired`，表示需要重新从头遍历。最后一页的
`next_cursor` 为 `null`。

两个订阅携带同一个分享链接时是同一个节点（ID 由链接派生），因此列表只报告一次，
并把组成员关系与健康观测合并；组同样把它当作一个成员。

`health` 与组报告的是同一套投影，按 transport / purpose / IP 版本区分——每个 IP 版本
有三个 purpose（`tcp`/`data`、`udp`/`dns`、`udp`/`data`），因此探测齐全的节点会报告
六条。
`subscription_tag` 为节点来源订阅，内联节点为 `null`；`provider_id` 指向该节点所属的
provider（见下）。节点管理（`POST`、`DELETE`）返回
`404 capability_not_supported`。

### 规则、providers 与 geodata

`GET /api/v1/rules` 返回**配置态**的规则，并包含 fallback。构建数据面的优化器会改写选择器
名字、把每个 `geosite`/`geoip` 引用展开成条目、并合并或注入自己的规则；导出那份结果等于
描述一套没人写过的规则，而且单行配置就可能膨胀到数 MB。因此该资源只报告配置形态，体积
保持在 KB 级。

配置规则为 `traffic:<index>`，fallback 为 `traffic:fallback`。`index` 跟随**配置顺序**，
而不是内核求值顺序——优化器可能合并相邻同出站规则并注入 sniff-punt 规则。关联规则只能靠
`generation_id` 加 `rule_id`，不能用表达式；`generation.changed` 之后要重新拉取。需要
拿到求值顺序规则的消费者（例如 routing trace）必须自行建立下标映射。该资源不分页：
`max_rules` 就是路由字典容量（1<<20），因此整个字典一定一次返回，也没有
`410 snapshot_expired`。

`GET /api/v1/providers` 按订阅 tag 归并节点。`node` 段与无 tag 的订阅合并为可编辑的
`inline` provider（`p_inline`），其他 tag 为 `p_` 加 tag 哈希，因此只要 tag 不变，
provider ID（以及节点的 `provider_id`）跨 reload 稳定。`node_count` 取自当前
generation；订阅没有产出任何 dialer 时 `status` 为 `"stale"`，而不是编造更新时间。
分页复用节点那套绑定 generation 的 cursor。`can_refresh`、`can_manage` 为 `false`，
所以 `POST /api/v1/providers`、`DELETE /api/v1/providers/{provider_id}`、
`POST /api/v1/providers/{provider_id}/refresh` 返回
`404 capability_not_supported`。

`GET /api/v1/geodata` 报告 dae 实际加载的 geoip/geosite 文件大小、mtime 与 SHA-256。
摘要会缓存到文件变化为止，因此轮询开销很小。`can_update` 为 `false`：资源来自安装包，
`POST /api/v1/geodata/update` 返回 `404 capability_not_supported`。

### DNS 缓存、日志、规则与查询

DNS 资源读取运行中的解析器，因此只有 DNS controller 工作时可用，否则返回
`503 temporarily_unavailable`。

`GET /api/v1/dns/cache` 列出运行时缓存，支持 `name`、`domain`、`type`、
`include_expired`、`limit`（1–1000，默认 100）与不透明 `cursor`。条目 ID 为 `de_`
加缓存键哈希，是唯一稳定句柄，可直接用于 `DELETE /api/v1/dns/cache/{entry_id}`。
`DELETE /api/v1/dns/cache?name=` 可再用 `type` 收窄，`POST /api/v1/dns/cache/flush`
清空缓存；两者都返回 `{matched, deleted}`，因为命中与删除之间条目可能已被替换或已消失。

`GET /api/v1/dns/log` 返回有界环形的客户端解析记录，最新在前，支持 `name`、`type`、
`src`、`limit`（默认 200，上限为 `dns_log.max_page_size`）与 cursor。诊断用的
`/dns/query` 不写入该环。cursor 指向已被挤出环的记录时返回 `410 snapshot_expired`，
客户端应丢弃 cursor 重新开始遍历。

`GET /api/v1/dns/rules` 是当前 generation 的只读 DNS 规则字典（request 与 response 各自
带 fallback）。`POST /api/v1/dns/query` 走与数据面相同的路由与缓存解析一个域名：
`cache_mode` 为 `normal` 或 `bypass`，`upstream` 按名称强制指定某个已配置上游，答案带
`cached`、`upstream`、`elapsed_ms` 与缓存条目 ID。查询限制为每个调用方每分钟 60 次
（超出返回 `429 rate_limited` 并带 `Retry-After`），单次超时 5 秒。

### 连接与 flows

`GET /api/v1/connections` 列出运行中的用户态 flow；`visibility` 为 `partial`，因为
内核旁路流量不进入用户态。`type`（tcp/udp/all）、`src`（IP 字面量，不是 host:port）与
`limit`（默认 100）用于过滤，`total_tcp` / `total_udp` 是截断前的匹配数，
`truncated` 表示 limit 是否隐藏了条目。`can_close` 为 `true`：
`DELETE /api/v1/connections/{connection_id}` 关闭单条，`DELETE
/api/v1/connections?type=…&src=…` 关闭一批。批量接口在没有任何过滤条件时拒绝执行，
除非显式 `all=true`；单次最多关闭 `max_bulk_close`（1000）条。

`GET /api/v1/flows` 读取已关闭 flow 的历史：2048 条、保留 900 秒的环形记录，最新在前，
可按 `network`、`state`、`connection_id` 过滤，带 `limit`（默认 100）与不透明 cursor。
`GET /api/v1/flows/{flow_id}` 返回单条，已过期返回 `410 flow_expired`。flow ID 为 `f_`
加端点与开始时间的哈希，连接通过 `flow_id` 引用同一 ID。flow 详情里的 `trace` 在本
引擎恒为 `disabled` 且 `missing: ["not_instrumented"]`：trace 所需证据未被记录。

### 事件流与日志流

`GET /api/v1/events` 与 `GET /api/v1/logs` 是 SSE 流。两者都以 `stream.ready` 开场，
其 `id` 就是续传 cursor；客户端带 `Last-Event-ID` 重连会从该帧之后继续，未知或已淘汰的
cursor 返回 `409 event_cursor_expired`，客户端应丢弃它建立新的基线。慢客户端会被断开，
而不是允许它阻塞引擎。

事件流发布 `runtime.updated`、`operation.updated`、`generation.changed`，记录在有界环中
保留 300 秒。日志流镜像 dae 自身日志，级别 `trace`–`error`，`target` 可收窄到单个 logger。
字段名包含 `secret`、`token`、`authorization`、`password`、`cookie` 的日志字段会被丢弃，
消息文本中的 bearer token 与 URL query 会被脱敏，因此该流不会变成凭据泄漏渠道。日志环
保留 1024 条、300 秒。

### 探测

`POST /api/v1/probes` 启动异步探测，与 reload 操作一样返回 `202` 并带 `Location` 与
`Retry-After: 1`，结果通过 `GET /api/v1/operations/{operation_id}` 获取。`kind` 为
`tcp_connect`、`http` 或 `dns`，`transport` 为 `tcp`、`udp` 或两者（`tcp_connect` 与
`http` 只支持 TCP，`dns` 两者皆可）。`node` 目标探测单个节点；`group` 目标探测组成员，
可用 `members` 收窄（`direct` 与 `leaves` 表示组本身）。

每条结果给出 `healthy` 或 `unavailable`、`latency_ms`、实际应答的 transport 与 IP 版本，
以及 `member_id` 中的目标 ID。探测通过节点自己的 dialer 在用户态发起，因此测的是代理
实际走的路径，而不是宿主机直连。工作量有上限：同时运行 4 个，最多排队 16 个（都满时返回
`503 temporarily_unavailable` 并带 `Retry-After`），调用方限制为每分钟 120 次
（`429 rate_limited`），单个任务最多展开 256 个成员、返回 512 条结果，并在 30 秒后停止，
因此一个超大组不会永久占住队列。这些数字就是 `capabilities.probes.limits` 所声明的值。

### 运行时汇总与出站计数器

`GET /api/v1/runtime` 混合了两个观测面，并用 `traffic.observed_by: "mixed"` 如实说明：
用户态 relay 统计的是 payload 字节，eBPF 数据面统计的是不经用户态转发的流的链路字节。
`traffic.planes.userspace` 与 `traffic.planes.kernel_direct` 把两者分开，且相加精确等于
`traffic.bytes`；需要单一口径的读者应取 plane，而不是混合总量。

`process.cpu_percent` 是守护进程在最近一个 1 秒采样区间内的 CPU 占用，按**单核**百分比计：
`100` 表示一个核心跑满，多核主机可能超过 100。它是区间增量而非生命周期均值，因此在拿到两次
采样之前为 `null`；reload 会重启该区间，期间短暂回到 `null`。`process.pid` 仅在
`detail=full` 时返回。

`traffic.counter_since` 与 `runtime/outbounds.counter_since` 是同一个进程级边界，且都跨
reload 保留。per-outbound 计数器是进程级、流量存储是 generation 级，因此 generation
交接时会继承总量，而不是从零重来。

`GET /api/v1/runtime/outbounds` 按出站报告 `active_connections`、
`total_connections`、`upload_bytes`、`download_bytes`、`errors`。builtin `direct`
行涵盖数据面不经用户态转发的字节，因此 `sum(outbounds)` 与
`runtime.traffic.bytes` 只差 DNS 流量（它不属于任何出站）。这些字节对旁路流是链路字节、
对真正进入用户态的 `must_direct` 流是 payload 字节，单条流内部不会混合。

### 内存

`GET /api/v1/runtime/memory` 报告 `process.rss_bytes`、cgroup v2 读数以及 dae 的 eBPF
对象占用的内核内存；`GET /api/v1/runtime/memory/history` 返回保留的历史序列。

cgroup 部分取决于系统。cgroup v2 只有在父级委派控制器之后
（`echo +memory > cgroup.subtree_control`），子 cgroup 才会出现 `memory.current`、
`memory.max`、`memory.events`。未委派时 `cgroup` 为 `null`，
`capabilities.resources.runtime_memory` 也不会声明 cgroup 指标：引擎只报告能读到的值，
从不编造。内存按分配计费，因此应在启动 dae 之前完成委派；此前分配的页不会被追溯计费。

`memory.max` 的值为字面量 `max` 表示无限制，这与"系统不提供 cgroup 内存"不是一回事：
此时上限指标仍然声明，`cgroup.limit_bytes` 为 `null`，客户端可以显示"未设上限"而不是
"未知"。

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
