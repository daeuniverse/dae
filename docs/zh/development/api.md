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
- `PATCH /api/v1/groups/{group_id}/config`（受配置写入闸门约束）
- `PUT /api/v1/groups/{group_id}/selection` — 切换 `select` 组成员，或在自动策略上
  pin 一个成员
- `DELETE /api/v1/groups/{group_id}/selection` — 取消 pin；`select` 组返回
  `409 state_conflict`，`fixed` 返回 `422 unsupported_value`
- `GET /api/v1/runtime/outbounds` — 按出站统计，reload 后继续累计
- `GET /api/v1/runtime/memory` — 进程、cgroup v2 与 eBPF 内存
- `GET /api/v1/runtime/memory/history?window_seconds=&max_points=`
- `GET /api/v1/runtime/direct-stats` — 需开启的直连流量计数
- `GET /api/v1/datapath` — eBPF 挂载点、routing generation 与 map 占用
- `GET /api/v1/nodes?group_id=&limit=&cursor=`
- `GET /api/v1/nodes/{node_id}`
- `POST /api/v1/operations/reload`
- `POST /api/v1/operations/suspend`
- `POST /api/v1/operations/resume`
- `GET /api/v1/operations/{operation_id}`
- `GET /api/v1/rules` — 当前 generation 的配置态路由规则
- `POST /api/v1/routing/trace` — 按当前 generation 模拟路由；仅支持 `resolve: "none"`
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
`DELETE /api/v1/providers/{provider_id}`、`POST /api/v1/geodata/update`
返回 `404 capability_not_supported`，与 `providers.can_manage`、
`geodata.can_update` 恒为 `false` 一致：dae 不通过 API 创建或删除订阅。

`POST /api/v1/nodes`、`DELETE /api/v1/nodes/{node_id}` 与
`POST /api/v1/providers/{provider_id}/refresh` 已实现，但受配置写入闸门约束：
`nodes.can_manage` 与 `providers.can_refresh` 随 `api.config_write` 与受管目录布局一起为真。
三者都排队一个 reload，分别以 `202` + `node_create` / `node_delete` / `provider_refresh`
操作返回；`DELETE` 对未知 id 保持幂等（`200 {"deleted": 0}`）。

`/api/v1/runtime/settings` 与 `/api/v1/auth*` 返回 `404 capability_not_supported`。
路由模拟的能力随当前 generation 提供；超过 4096 个规则步骤时不会构建模拟器。
`routing_trace.available` 为 `false` 时，
`POST /api/v1/routing/trace` 返回同一错误。它只模拟、不执行连接或 DNS 查询，且当前仅支持
`resolve: "none"`；`resolve: "live"` 返回 `422 unsupported_value`。每主体每分钟最多 30 次，
全局每分钟最多 120 次，超限返回 `429 rate_limited` 和 `Retry-After`。

配置支持源级编辑及受限的组配置编辑：`GET /api/v1/config`、
`GET /api/v1/config/sources[/{source_id}]`、
`PUT /api/v1/config/sources/{source_id}`（需 `If-Match`）与 `POST /api/v1/config/validate`。
仅当 `api.config_write = true` 且配置目录符合受管布局（`config.dae` 引入 `config.d/*.dae`
与 `api.dae`）时才允许写入；否则返回 `403 permission_denied` 并附 `details.reason`，且不写盘。
组配置补丁使用 `application/json-patch+json`，需要从组配置 `ETag` 传入强 `If-Match`；
目前仅允许修改 `/config/check_interval`（秒）和 `/config/tolerance`（毫秒）。
成功修改会排队 reload，返回 `202` 与 `group_update` operation；`groups.config_patch` 和组的
`capabilities.mutable_config` 会反映当前是否可写。
与契约的有意偏离：

- `api.dae` 被隐藏：不出现在 `sources[]` 中，其 id 返回 `404 resource_not_found`，与未知 id 一致。
  能力信息通过 `x-dae.hidden_sources` 体现。
- `config.dae` 只读（`entry_source`）。替换时不得修改 `api` 段。
- `GET` 读取磁盘文件，而非已接受的快照。其 `revision` 与
  `runtime.generation.config_revision` 使用同一个函数，因此两者可比：磁盘内容就是引擎已加载
  的内容时二者相等，写入尚未 reload 时二者不同。

规则与 DNS 规则通过替换其所属源文件（`routing.dae`、`dns.dae`）来编辑，API 不提供行级编辑。

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
分页复用节点那套绑定 generation 的 cursor。订阅的 `can_refresh` 为 true，配置写入
可用时 `can_manage` 为 true，因此 `POST /api/v1/providers/{provider_id}/refresh`
会排队一个 `provider_refresh` 操作。刷新会重新拉取订阅；拉取失败时保留上一次成功的
节点，避免切断正在运行的 generation，同时不把失败报成成功：`status` 为 `"stale"`，
`last_error` 给出原因，`updated_at` 是最后一次尝试的时间。其余情况下
`can_refresh`/`can_manage` 为 `false`，相关端点返回 `404 capability_not_supported`。

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

`upload_bytes` / `download_bytes` 只对 dae 在用户态转发并计数的 flow 有值：UDP 流与数据面
直接处理的流量都留空（`null`）。因此任何由这两个字段聚合出的「按设备/域名流量排行」都只
覆盖链路的一部分，dae 不提供设备级流量总量。`api.disable_connection_bytes: true` 会让这
两个字段恒为空，使仅靠该数据绘制的面板没有可直接呈现的不完整数字；连接的其余字段不受
影响。

`GET /api/v1/flows` 读取已关闭 flow 的历史：2048 条、保留 900 秒的环形记录，最新在前，
可按 `network`、`state`、`connection_id` 过滤，带 `limit`（默认 100）与不透明 cursor。
与 DNS 日志/缓存一样，cursor 记录的是客户端已收到的最后一条记录而不是偏移量，因此遍历期间
在表头新增的记录不会让后续页重复或跳过；锚点记录已被挤出环时返回 `410 snapshot_expired`。
`GET /api/v1/flows/{flow_id}` 返回单条，已过期返回 `410 flow_expired`。flow ID 为 `f_`
加端点与开始时间的哈希，连接通过 `flow_id` 引用同一 ID。flow 详情里的 `trace` 在本
引擎恒为 `disabled` 且 `missing: ["not_instrumented"]`：trace 所需证据未被记录。

### 事件流与日志流

`GET /api/v1/events` 与 `GET /api/v1/logs` 是 SSE 流。两者都以 `stream.ready` 开场，
其 `id` 就是续传 cursor；客户端带 `Last-Event-ID` 重连会从该帧之后继续，未知或已淘汰的
cursor 返回 `409 event_cursor_expired`，客户端应丢弃它建立新的基线。cursor 还绑定到签发它
的实例与仍然保留的位置：重启前的 cursor、或所指记录已被环形缓冲淘汰的 cursor 都会过期，
而不是静默续传并漏掉失效通知。慢客户端会被断开，而不是允许它阻塞引擎。

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
以及 `member_id` 中的目标 ID。三种 kind 各自测它名字所说的东西：

- `tcp_connect` 用直连 dialer 连节点自己的服务器地址（不经过该节点），报告该服务器是否
  接受连接；没有服务器地址的出站（builtin `direct` 组）回退为经由节点发起一次拨号。
- `http` 经由节点发出真实 `GET`，要求返回小于 500 的响应。
- `dns` 经由节点发出真实查询，要求收到格式正确的应答。

探测通过节点自己的 dialer 在用户态发起，因此测的是代理
实际走的路径，而不是宿主机直连。工作量有上限：同时运行 4 个，最多排队 16 个（都满时返回
`503 temporarily_unavailable` 并带 `Retry-After`），调用方限制为每分钟 120 次
（`429 rate_limited`），单个任务最多展开 256 个成员、返回 512 条结果，并在 30 秒后停止，
因此一个超大组不会永久占住队列。这些数字就是 `capabilities.probes.limits` 所声明的值。

### 运行时汇总与出站计数器

`GET /api/v1/runtime` 的 `traffic.observed_by` 为 `"userspace"`：`traffic.bytes` 中的
每个字节都由用户态 relay 统计，因此是 payload 字节。数据面不经用户态转发的流量（内核直接
路由的流，或从未到达 relay 的 `must_direct` 流量）**不**计入。因此在直连为主的部署上，这个
数字会低于真实链路速率。这是有意的取舍：另一条路是在数据面里维护每包计数与直连流索引，
而所有安装（包括从不开启该 API 的）都要为它付费。

速率由每秒运行一次的采样器基于进程总量计算，转发路径上的每次记账只需一次原子加。

`process.cpu_percent` 是守护进程在最近一个 1 秒采样区间内的 CPU 占用，按**单核**百分比计：
`100` 表示一个核心跑满，多核主机可能超过 100。它是区间增量而非生命周期均值，因此在拿到两次
采样之前为 `null`；reload 会重启该区间，期间短暂回到 `null`。`process.pid` 仅在
`detail=full` 时返回。

`traffic.counter_since` 与 `runtime/outbounds.counter_since` 是同一个进程级边界，且都跨
reload 保留。流量存储与 per-outbound 计数器一样是进程级：reload 之后仍存活的连接继续计入
`/runtime` 读取的数字，总量与速率既不会停在交接时刻，也不会从零重来。

`GET /api/v1/runtime/outbounds` 按出站报告 `active_connections`、
`total_connections`、`upload_bytes`、`download_bytes`、`errors`。builtin `direct`
行涵盖真正进入用户态的 `must_direct` 字节，因此 `sum(outbounds)` 与
`runtime.traffic.bytes` 只差 DNS 流量（它不属于任何出站）。开启 `api.direct_stats`
时该行还会带上内核直连的链路字节，此时总和会比 `runtime.traffic.bytes` 多出这部分。
builtin `block` 行不再暴露：被封锁的流量在数据面被直接丢弃，永远不会进入任何计数器，
该行只可能恒为 0。

### 直连流量

`GET /api/v1/runtime/direct-stats` 返回 `enabled`、`up_bytes`、`up_packets`、
`down_bytes` 与 `down_packets`（十进制字符串）。只有开启 `api.direct_stats` 时才有意义：
`control/kern/direct_stats.c` 里的观测程序在 dae 已绑定的 WAN/LAN 接口上紧挨 tproxy 运行，
只读 `conn_state_map`、不写入，统计已经被标记为直连 passthrough 的流。开关关闭时钩子不存在，
计数器恒为 0。

数字是链路字节且只是下界：观测程序在 tproxy 之前运行，每条流的第一个包和重启前已存在的流
都会漏计，ICMP/分片被跳过；NAT 网关上单请求交互的回包侧，要等第二次上行重新填充 LRU 流索引
后才能识别。该数字不会并入 `runtime.traffic`，后者仍然只统计 userspace 可见流量。
观测计数会并入 `GET /api/v1/runtime/outbounds` 的内置 `direct` 行，因此只读既有
资源的控制台无需认识本端点也能看到直连流量。该行此时是混合口径：内核直连的链路字节
加上 relay 统计到的 `must_direct` payload 字节。

#### 开销

直连流量不会进入用户态，所以直连吞吐再高也不会增加用户态 CPU 或堆内存。开销有上界，
且都在内核里：

- 内存是与流量无关的固定上限。`direct_stats_map` 是 4 个 `u64` 的 per-CPU 数组；
  `direct_reverse_map` 是 LRU 哈希，上限 131072 条（key 24 字节、value 8 字节，外加内核
  哈希开销，最多约十 MB 量级），流量暴增时淘汰旧条目而不是继续增长；`conn_state_map`
  是 tproxy 自己的表，通过 map replacement 复用，不会再分配一份。
- CPU 与包速率成正比，而不是字节速率。入向程序按接口角色选择：仅 LAN 的钩子只查上行 tuple，
  仅 WAN 的钩子只查回包 tuple，同时承担两种角色的接口运行合并版本。入向包对钩子能看到的每个
  方向各查一次 `conn_state_map`，直到某个方向命中即止（角色专用钩子一次，合并版本最多两次）；仅当流是直连时才做一次 per-CPU 计数更新（无原子操作，不共享 cacheline）。
  被 tproxy 标记为代理的流在命中条目后直接结束，不会触碰 `direct_reverse_map`，因此代理流量
  只付查找开销、没有 map 更新。`direct_reverse_map` 只在两个方向都没有 `conn_state_map`
  条目时才会被查询（NAT 网关回包场景），且只为直连流更新。WAN 角色多运行一个 egress 程序，
  对转发包提前退出，其余情况做一次查找。只有在极高包速率的小包场景下开销才可能变得可见；
  大包的批量传输主要受网卡与协议栈支配。
- 失败被隔离：对象加载失败时 dae 只打印告警、跳过钩子并继续转发，API 返回 0。
- `api.direct_stats` 关闭时不会加载对象，也不挂任何钩子。

以上结论来自阅读程序本身，不是基准测试结果。要在真实系统上度量，可设置
`sysctl kernel.bpf_stats_enabled=1`，再用 `bpftool prog show` 读取 `dae_direct_stats_*`
程序的 `run_cnt` 与 `run_time_ns`；`bpftool map show` 可查看 map 占用的内存。

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
