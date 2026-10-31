# dae Native API 适配计划（api-standardize）

> 目标契约：`github.com/daeuniverse/api-standardize`（branch `honk`，contract `0.1.0-draft`）
>
> 本文是实施计划，不是最终契约文档。契约以 `api-standardize/source/openapi.yaml` 为准。
>
> 实现状态（2026-10-31）：P0-1 ~ P0-6、P1-1 ~ P1-4、P2 的 nodes / 组健康 / can_override，以及 P3-1 ~ P3-12 全部完成（P0-6 为自托管前端 `/ui/`）。capabilities 中所有已接入资源按 provider 是否接入返回 `available: true`：`groups`、`traffic_history`、`operations`、`runtime_outbounds`、`runtime_memory`、`memory_history`、`datapath`、`rules`、`providers`、`geodata`、`dns_cache`、`dns_log`、`dns_rules`、`dns_query`、`connections`、`flows`、`events`、`logs`、`probes`。仍声明不可用的是配置读写（`config*`）、`runtime/settings`、`routing/trace`、`auth/*`；providers 的增删/refresh 与 geodata 的 update 按只读定位返回 `404 capability_not_supported`。P0-2 的 ServeMux 路径模式仍未采用（等价于 path switch）。剩余工作：契约 schema 测试（固定 `openapi.yaml` 到 testdata）与端到端集成测试。

## 1. 结论与范围

### 1.1 现状

- dae 目前没有原生 HTTP 控制面，只有 `pprof_port` 的 `net/http/pprof` listener。
- 没有 instance id、config revision、runtime generation id。
- 组策略支持 `random`、`fixed`、`min`、`min_avg10`、`min_moving_avg`，没有可运行时切换成员的 `select` 组。
- 已有可复用能力：
  - `control.SnapshotRuntimeStats`：上传/下载总量、速率、连接数、历史样本。
  - `control.SnapshotNodeLatencies`：节点延迟快照。
  - `control.ActiveTCPConnections`、`DefaultUdpEndpointPool.Len()`。
  - reload / suspend 信号机制（`SIGUSR1` / `SIGUSR2`）。
  - eBPF datapath generation（`datapathGeneration`）。

### 1.2 本期范围

按需求确定：

1. 增加 `select` 组。
2. 不涉及配置编辑与保存功能。
3. 使用独立的顶级 `api` 配置段（不同于 honk 的 `experimental.native_api`）。
4. 支持自托管前端：固定挂载 `/ui/`，目录由 `api.ui` 配置。

建议首期实现：

| 模块 | 内容 |
|---|---|
| `base` profile | discovery、version、capabilities、runtime |
| `groups` | 只读 group 资源 + selector 的运行时 selection |
| `operations` | reload / suspend / resume |
| `traffic_history` | 运行时流量历史 |
| `ui` | 自托管前端：`/ui/` 静态托管（公开），其余非 `/api` 路径 302 到 `/ui/` |
| 安全 | token 认证、CORS、Host/Origin 校验、错误 envelope；非 loopback 必须 secret |
| 可观测 | 访问日志：成功 debug、拒绝/5xx info/error、每 60s 汇总一行 |

明确不做：

- `GET /api/v1/config`、`/config/validate`
- `PATCH /groups/{group_id}/config`
- `POST/DELETE /nodes`、provider 增删
- geodata 设置、runtime settings PATCH
- flows、connections、events、logs、DNS cache/rules、probes
- `full_transparency` profile

> `GET /groups/{group_id}/config` 是只读，用于满足 groups 资源；不属于“配置编辑/保存”。

## 2. 关键设计决策

### 2.1 顶级 `api` 配置段

```dae
api {
    enabled: true
    listen: '127.0.0.1:9527'
    secret: 'change-me'
    allow_anonymous_loopback: false
    allow_origins: 'http://localhost:5173,https://ui.example.com'
    allowed_hosts: 'localhost,127.0.0.1,api.example.com'
    ui: '/usr/share/doona'      # 可选：在 /ui/ 托管已构建的前端
}
```

字段说明：

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `false` | 避免旧配置升级后自动暴露 API；`Config.Marshal` 往返安全 |
| `listen` | string | `127.0.0.1:9527` | 数字 IP + 端口（1–65535）；不接受 hostname 或 `:port` 简写 |
| `secret` | string | 空 | 非空 = token mode；所有非 discovery 请求必须 `Authorization: Bearer <secret>` |
| `allow_anonymous_loopback` | bool | `false` | 仅当 `secret` 为空且实际监听地址为 loopback 时，允许无凭证访问 |
| `allow_origins` | []string | 空 | 逗号分隔；空表示关闭跨域 |
| `allowed_hosts` | []string | 空 | DNS Host 白名单；防 DNS rebinding / 反向代理 Host 校验；省略端口按 80 处理 |
| `ui` | string | 空 | 已构建前端的绝对目录；在 `/ui/` 无凭证托管，非 `/api` 路径 302 到此。目录不可用（缺失/无 `index.html`）只 warning，不阻断启动 |

设计约束：

- `api` 是顶级 section，不是 `global` 的子项，也不是 `experimental.native_api`。
- `enabled=false` 时不监听。
- `enabled=true` 时必须满足以下之一，否则 `dae validate` / 启动失败：
  1. `secret` 非空（token mode）；
  2. `secret` 为空 + `allow_anonymous_loopback: true` + 实际监听地址为 loopback。
- 非 loopback 监听必须 `secret` 非空；`allow_anonymous_loopback` 不能替代 `secret`。
- `0.0.0.0` / `::` 等 wildcard bind 视为非 loopback，必须 `secret`。
- `secret` 非空时，即使监听 loopback，所有非 discovery 请求也必须带 `Authorization: Bearer <secret>`。
- discovery（`GET /api`）是唯一公开端点；`secret` 模式下 version / capabilities 也需要 Bearer，其他资源全部需要。
- dae 不提供 TLS listener。按契约，非 loopback 的 bearer 传输必须由 listener 或受信任的本机反向代理终止 TLS；dae 不在配置里强制 TLS，但非 loopback 启动时应打印 warning 提醒部署方确认 TLS 终止。
- API listener 启动在 dae 进程初始 netns（host netns），不要放进 `withDaeNetnsRequiredFunc` 的 dae netns。
- 路由边界：只有 `/api` 与 `/api/v1/...` 属于控制面（按配置认证）；其余路径一律是页面访问。
- 自托管前端（`ui`）：
  - `ui` 只接受绝对路径（相对路径在 `dae validate` 报错）；目录不存在或缺 `index.html` **不**报错、**不**退出：启动时 warning，`/ui/` 返回 `404`，API 与代理照常运行。
  - 固定挂载在 `/ui/`；`/`、`/ui` 以及其他任何非 `/api` 路径都 302 到 `/ui/`（不会落到 401）。
  - 静态文件公开（浏览器无法给 `<script src>` 附带 Bearer），但 Host/Origin 校验照旧；前端发出的 API 请求仍必须带 token（token 不注入页面）。
  - 仅“无扩展名的未命中”回退到 `index.html`；缺失的资源/字体/manifest/service worker 返回 `404`，不回退 HTML；不提供目录列表。
  - 越界路径（如 `/ui/../api/v1/runtime`）返回 `404`，不会落到 API 路由。
  - 缓存：`assets/` 下按 immutable 缓存一年，其余 `no-cache`；`.webmanifest` 用 `application/manifest+json`。
  - 与 honk 的 `ui: embedded` 不同：dae 只托管管理员配置的外部目录，不内嵌资源、不下载前端。
- `api` section 的所有字段建议 restart-required：reload 检测到 `api` 变化时拒绝或保留旧配置并 warning（与 honk 的 native_api 行为一致）。如果后续要实现热更新，只对 `secret` / `allow_origins` / `allowed_hosts` 做原子切换；`listen` 与 `ui` 始终需要重启。

### 2.2 `select` 组语义

```dae
group {
    proxy {
        filter: name(keyword: 'HK')
        policy: select      # 默认选第 0 个成员
        # policy: select(1) # 初始选第 2 个成员
    }
}
```

- `select` 是新的 `DialerSelectionPolicy`。
- 运行时选择按 transport 分开：`tcp`、`udp`；DNS UDP 跟随 `udp`。
- 选择只存在内存，不写配置文件；reload / restart 后恢复为配置默认索引。
- `select` 组忽略 `excluded`，与 `fixed` 一样遵循用户显式意图。
- kernel 侧按 optimistic alive 处理，避免组被误判为不可用。
- 一期不对自动策略开放 `can_override`；`urltest` / `random` 的 `PUT selection` 返回 `422 unsupported_value`。

### 2.3 策略映射

| dae 配置 | `policy.kind` | `can_select` | `can_override` | 说明 |
|---|---|---|---|---|
| `select` / `select(n)` | `selector` | true | false | `PUT selection` 生效；`DELETE` 返回 `409 state_conflict` |
| `fixed(n)` | `fixed` | false | false | 固定成员，不能在运行时切换 |
| `random` | `random` | false | false | 每连接随机，无稳定 selection |
| `min` / `min_avg10` / `min_moving_avg` | `urltest` | false | false | 一期不开放 pinning |

### 2.4 与 honk native_api 的对应关系

| honk `experimental.native_api` | dae `api` | 说明 |
|---|---|---|
| `enabled` | `enabled` | 默认 false |
| `listen` | `listen` | 数字 IP + 端口；默认 `127.0.0.1:9527` |
| `secret` | `secret` | 非空 = token mode |
| `allow_anonymous_loopback` | `allow_anonymous_loopback` | 仅 secretless loopback 生效 |
| `allow_origins` | `allow_origins` | 精确 origin |
| `allowed_hosts` | `allowed_hosts` | DNS Host 白名单 |
| `password_auth` | 不实现 | dae 首期只做 token mode |
| `ui`（embedded） | `ui`（目录） | 只托管管理员配置的外部目录，不做内嵌资源 |
| `record_*` / `config_write` | 不实现 | 不做 flows/logs/DNS log/配置写入 |
| 所有字段 restart-required | `api` 所有字段 restart-required | reload 检测到变化时拒绝或保留旧 listener |

> 字段名与语义直接对齐 honk `experimental.native_api`（`crates/honk-config/src/experimental.rs`），
> 而 honk 这两个字段落实的是契约 `docs/api-config.md` 的两条安全要求：精确 origin 白名单
> （空列表=关闭跨域）与 Host 校验（防 DNS rebinding）。语义源自通用 Web 约定：`allow_origins`
> 对应 CORS 的 `Access-Control-Allow-Origin` 精确值域，`allowed_hosts` 对应 Host 白名单
> （Django `ALLOWED_HOSTS` / Rails `config.hosts` / Vite `server.allowedHosts` 同一套路）。

> 与 honk 一致：非 loopback 必须有 `secret`；secretless 匿名仅限 loopback 且显式 `allow_anonymous_loopback: true`。TLS 不在 listener 配置中强制，由受信任反向代理终止。

## 3. 分阶段任务清单

### P0-1 配置层

- [x] `config/config.go`
  - [x] 新增 `Api` struct。
  - [x] `Config` 增加 `Api Api` 字段，tag 为 `mapstructure:"api" desc:"ApiDesc"`。
  - [x] 字段：`Enabled`、`Listen`、`Secret`、`AllowAnonymousLoopback`、`AllowOrigins`、`AllowedHosts`。
- [x] `config/decode.go`
  - [x] `configSectionSpecs` 增加 `{name: "api", decode: decodeApiSection}`。
- [x] `config/desc.go`
  - [x] 增加 `ApiDesc`。
  - [x] `SectionSummaryDesc` 增加 `api`。
  - [x] `SectionDescription` 增加 `"ApiDesc": ApiDesc`。
  - [x] `GroupDesc.policy` 增加 `select` 说明。
- [x] `config/marshal.go` / `config/outline.go`
  - [x] 确认 `dae export outline` 包含 `api` 字段。
  - [x] 确认 `Config.Marshal` 输出 `enabled:false` 时重新解析不会启用 API。
- [x] `cmd/validate.go` / `cmd/run_config.go`
  - [x] 校验 `listen` 为数字 IP + 端口，端口 1–65535；拒绝 hostname 与 `:port` 简写。
  - [x] `enabled=true` 时必须有认证模式：
    - [x] `secret` 非空（token mode）；或
    - [x] `secret` 为空 + `allow_anonymous_loopback: true` + 实际监听地址为 loopback。
    - [x] 两者都不满足 → 报错。
  - [x] 非 loopback + `secret` 为空 → 报错；`allow_anonymous_loopback` 不能替代 `secret`。
  - [x] wildcard bind（`0.0.0.0` / `::`）按非 loopback 处理，必须 `secret`。
  - [x] 非 loopback + `secret` 长度 < 16 bytes → warning（不拒绝）。
  - [x] `secret` 必须是可见 ASCII，且不含空白、逗号或控制字符（需匹配 HTTP bearer token 语法）。
  - [x] `secret` 非空时 `allow_anonymous_loopback` 不生效（文档写明；可选择 warning）。
  - [x] `allow_origins` 必须是绝对 `http(s)` origin，无 path/query/fragment/userinfo/通配符。
  - [x] `allowed_hosts` 必须是明确 Host authority，无 scheme/path/credentials/通配符；省略端口按 80 处理。
  - [x] 非 loopback + `secret` 允许启动，但启动时 warning：确认 TLS 由受信任的本机反向代理终止；dae 不提供 TLS listener。
- [x] `cmd/run.go`
  - [x] `conf.Api.Enabled` 时启动 API server。
- [x] `cmd/run_reload_worker.go` / reload manager
  - [x] reload 时比较新旧 `conf.Api`；变化时拒绝 reload 或保留旧 listener 并 warning，不做部分 listener 重启。
- [x] 测试
  - [x] 配置解析与默认值。
  - [x] 非法 listen / 非 loopback 无 secret。
  - [x] `secret` 为空且未开启 `allow_anonymous_loopback` 时启动失败。
  - [x] `secret` 为空 + `allow_anonymous_loopback=true` 但 listen 非 loopback 时启动失败。
  - [x] `dae validate -c` 覆盖 API 配置。
- [x] 文档
  - [x] `docs/en/configuration/api.md`
  - [x] `docs/zh/configuration/api.md`
  - [x] 中英文 README 配置示例。

### P0-2 API server 骨架

- [x] 新增包 `component/nativeapi`（或 `control/nativeapi`）。
- [ ] 使用标准库 `net/http` + Go 1.22+ `ServeMux` 路径模式。（当前用 path `switch` 实现，功能等价；未采用 ServeMux pattern）
- [x] `http.Server` 配置 `ReadHeaderTimeout`、`IdleTimeout`、`MaxHeaderBytes`。
- [x] 生命周期：
  - [x] control plane 创建、`runtimeSupervisor` / `reloadManager` 可用后启动。
  - [x] reload 期间保持监听，不随 generation 重建。
  - [x] 进程退出 `Shutdown(ctx)`。
- [x] middleware：
  - [x] 认证。
  - [x] CORS 预检与 Origin/Host 校验。
  - [x] request target / header / body 大小限制。
  - [x] `Content-Type` 校验（`PUT /groups/{id}/selection`、`POST /operations/*`）。
  - [x] 统一 JSON 错误 envelope。
  - [x] `request_id` 生成。
  - [x] `Cache-Control: no-store`、`X-Content-Type-Options: nosniff`。
  - [x] 访问日志：每条请求 `debug`（method/route/status/elapsed_ms/request_id/remote_ip/bytes），拒绝与 `5xx` 记 `info`/`error` 并带 `error_code`，每 60 秒一行 `Native API traffic` 汇总；不记录请求头与查询串。
- [x] 已知但未实现的资源返回 `404 capability_not_supported`，不要落入普通 `404 resource_not_found`。
- [x] 测试：
  - [x] 路由 405 + `Allow`。
  - [x] 未实现资源 404 capability。
  - [x] 大小限制（request target / header / body）。
  - [x] `Content-Type` 校验测试（P1 的 `PUT selection` 与 `POST operations`）。

### P0-3 认证、安全、错误

- [x] 只实现 token mode，不实现 password/setup/login。
- [x] discovery 公开：
  - [x] 无凭证返回 public view。
  - [x] 有效凭证返回 full view。
  - [x] 无效凭证返回 `401 authentication_required`，不能降级成 public view。
- [x] 认证模式由 `secret` / `allow_anonymous_loopback` 决定：
  - [x] `secret` 非空（token mode）：所有非 discovery 请求，包括 loopback，都要求 `Authorization: Bearer <secret>`。
  - [x] `secret` 为空 + `allow_anonymous_loopback: true` + 实际 listener 为 loopback：允许无凭证；`auth.anonymous_loopback = true`。
  - [x] `secret` 为空 + `allow_anonymous_loopback: false`：启动失败（没有认证模式）。
  - [x] 非 loopback：`secret` 必须非空；匿名只允许 secretless loopback。
- [x] TLS 不在 dae 配置中强制：dae 只提供 plain HTTP listener；非 loopback 必须部署在受信任的 TLS 反向代理后（契约要求 bearer 传输由 listener 或受信任本机反向代理终止 TLS）。
- [x] token 常量时间比较。
- [x] `401` 响应带 `WWW-Authenticate: Bearer`。
- [x] CORS：
  - [x] 仅允许 `allow_origins` 精确 origin；空列表关闭跨域。
  - [x] 预检允许 `Authorization`、`Last-Event-ID`、`Content-Type`、`If-Match`、`Idempotency-Key`、`Accept`。
  - [x] 暴露 `Location`、`Retry-After`、`ETag`。
- [x] Host 校验：
  - [x] 默认 Host 必须匹配具体监听 authority。
  - [x] loopback listener 额外接受 `localhost`、`127.0.0.1`、`[::1]` 及同一端口。
  - [x] wildcard bind 接受任意 IP-literal Host 和 `localhost`（同一监听端口）；DNS 名称必须由 `allowed_hosts` 明确允许。
  - [x] 不信任 forwarded headers 作为授权依据。
- [x] Origin 校验：
  - [x] 仅自动允许与请求 Host 直接对应的 plain-HTTP origin；其他 origin 必须列入 `allow_origins`。
  - [x] secretless loopback listener 拒绝 `Sec-Fetch-Site: cross-site`，即使没有 Origin。
  - [x] 所有 native 请求拒绝未批准的 Origin，包括简单 Content-Type 的 POST。
- [x] 统一错误结构：

```json
{
  "error": {
    "code": "invalid_request",
    "message": "...",
    "details": null
  },
  "request_id": "req-..."
}
```

- [x] 状态码顺序：
  1. 认证 / 权限 / 路由：`401`、`403`、`404`、`405`
  2. 请求边界：`428`、`400`、`415`、`413`
  3. 幂等重放
  4. `412`
  5. 语义校验：`422`
  6. 当前状态：`409`
  7. `429` / `503`
- [x] `limits` 与实际中间件一致：
  - `max_request_target_bytes: 8192`
  - `max_header_bytes: 8192`
  - `max_json_body_bytes: 65536`
- [x] 日志不记录 Authorization / secret。

### P0-4 discovery / version / capabilities

- [x] `GET /api`
  - [x] full view：`name: "daeuniverse/native"`、`status: "draft"`、`api_major: 1`、`base_path: "/api/v1"`。
  - [x] `links` 包含契约要求的全部固定路径（即使资源不可用）：
    `version`、`capabilities`、`config`、`config_validate`、`runtime`、`runtime_outbounds`、`traffic_history`、`memory_history`、`logs`、`providers`、`rules`、`operations`、`geodata`。
  - [x] public view：只含 `name`、`api_major`、`links.auth_setup`、`links.auth_login`、`auth.mode`、`auth.setup_required`。
  - [x] `auth.mode = "token"`；`auth.anonymous_loopback` 按认证模式返回：secretless loopback + `allow_anonymous_loopback: true` 时为 true，否则 false。
- [x] `GET /api/v1/version`
  - [x] `api.name = "daeuniverse/native"`、`api.major = 1`、`api.status = "draft"`。
  - [x] `engine.name = "dae"`；`engine.version` 与 `dae -v` 完全一致（单一来源 `resolveBuildMetadata`：ldflags → module 版本 → `git-<sha>` → `"unknown"`）。
  - [x] `build`：`revision`/`target`/`built_at` 取自 Go build info，未知字段为 `null`；完全无信息时省略。
- [x] `GET /api/v1/capabilities`
  - [x] `profiles: ["base"]`，不要声明 `full_transparency`。
  - [x] `resources.runtime.available = true`。
  - [x] `resources.groups = { available: true, config_patch: false, selection: true, max_patch_operations: 1 }`。
  - [x] `resources.traffic_history = { available: true, max_window_seconds: 3600, max_points: 180 }`。
  - [x] `resources.operations = { available: true, retention_seconds: 3600, max_replay_keys: 1024 }`；
    `resources.reload` / `suspend` / `resume` available。
  - [x] `resources.config` / `config_validate` 设为 `{ available: false }` 或省略。
  - [x] 未实现资源用 `{ available: false }` 或省略。

### P0-5 runtime 资源

- [x] `GET /api/v1/runtime`，支持 `detail=summary|full`。
- [x] 进程级状态：
  - [x] `instance_id`：启动时生成，reload 不变。
  - [x] `lifecycle.started_at`、`uptime_seconds`。
  - [x] `lifecycle.state`：`starting` / `running` / `reloading` / `suspended` / `draining` / `degraded` / `failed`。（`degraded` 目前不会产生）
- [x] generation 元数据：
  - [x] `runtimeGeneration` 增加 `id`、`configRevision`、`activatedAt`。
  - [x] `generation.active_id` 每次 reload 生成新值。
  - [x] `config_revision` 用 accepted config 的 `Marshal` 结果做 SHA-256，作为 opaque string。
- [x] `datapath`：
  - [x] `kind: "ebpf"`。
  - [x] `state: "active"`（异常时 `degraded`）。（当前恒为 `active`；suspend 时未映射为 `disabled`）
  - [x] `visibility: "partial"`。
  - [x] `ebpf: null` 一期即可。
- [x] `traffic`：复用 `control.SnapshotRuntimeStats`
  - [x] `scope: "visible"`、`observed_by: "mixed"`（契约 `ObservedBy` 枚举为 `userspace` / `ebpf` / `mixed`；dae 的合计来自 userspace relay 的 payload 字节与 eBPF 直连计数两个观测面，故为 `mixed`）。
  - [x] `counter_since` = 当前 generation 激活时间。
  - [x] `connections.tcp = ActiveTCPConnections`、`connections.udp = UDPSessions`、`total` 为二者之和。
  - [x] `bytes.upload/download` 为十进制字符串。
  - [x] `rates.window_seconds = 1`，速率为字符串。（2026-10-30 修正：bucket 仅在记录流量时轮转，1s 速率在任何轮询节奏下都准确；此前只在 snapshot 时轮转，面板 5s 轮询下会读到 `0 B/s`）
- [x] `process`：
  - [x] `pid` 仅 `detail=full`。
  - [x] `cpu_percent` 后台采样或 gopsutil；未采样时 `null`。
- [x] `last_reload`：signal reload 和 API reload 都记录；无记录时 `null`。
- [x] 读取 active control plane 使用 supervisor 快照或 generation lease，避免 reload 期间使用已 retired 的 plane。

### P0-6 自托管前端

- [x] `config/config.go`：`Api` 增加 `UI`（`mapstructure:"ui"`）。
- [x] `config/api.go`：只要求绝对路径（相对路径报错）；目录不存在/缺 `index.html` 交由启动时 warning 处理；`enabled=false` 时忽略。
- [x] 路由：仅 `/api` 与 `/api/v1/...` 走认证；其余路径（含 `/`、`/ui`、任意深链）302 到 `/ui/`，不再返回 401。
- [x] `component/nativeapi`：固定前缀 `/ui/`；仅无扩展名的未命中回退 `index.html`；关闭目录列表；缺失资源/目录不存在返回 `404`（绝不返回 HTML，也不阻止启动）。
- [x] 缓存与类型：`assets/` 下按 immutable 缓存一年，其余 `no-cache`；`.webmanifest` 使用 `application/manifest+json`。
- [x] 安全：静态资源公开（浏览器无法给 `<script src>` 附带 Bearer），Host/Origin 校验照旧；API 调用仍要求 token；越界路径（`/ui/../api/v1/runtime`）返回 `404` 而不是落到 API。
- [x] 日志：`route=/ui/*`，非 2xx 追加截断后的 `target`，便于定位缺失资源。
- [x] 测试：index/重定向/资源/SPA 回退/目录 404/路径穿越/Host 校验/非 `/api` 路径一律 302（不再 401）/无 UI 时 404/缺 `index.html` 只 warning 且 API 照常/配置校验与解码。
- [x] 文档：`docs/*/configuration/api.md` 新增「Self-hosted UI / 自托管前端」，中英文 README 示例补 `ui`。
- [x] 实测：以 doona `v0.1.0-rc.3` 发布包为 `ui` 目录，`/ui/` 直接加载 UI 并以同源为后端，填 token 后仪表盘出数，Service Worker scope 为 `/ui/`。

### P1-1 `select` 组

- [x] `common/consts/dialer.go`
  - [x] 新增 `DialerSelectionPolicy_Select = "select"`。
- [x] `component/outbound/dialer_selection_policy.go`
  - [x] 解析 `select` 和可选的 `select(index)`。
  - [x] 复用 `FixedIndex` 作为初始成员索引。
- [x] `component/outbound/dialer_group.go`
  - [x] 增加 per-transport 运行时选择状态（tcp/udp 原子索引）。
  - [x] `_select` 增加 `Select` case，按 `networkType.L4Proto` 选择，忽略 `excluded`。
  - [x] `policyNeedsAliveState` 对 `select` 返回 `false`。
  - [x] `groupPublishesOptimisticAlive` 对 `select` 返回 `true`。
  - [x] `selectionNetworkTypes` 对 `select` 按 `fixed` 处理，不做 DNS UDP → TCP 回退。
  - [x] 新增 `SetSelection(network, index)`、`Selection(network)`、`SelectionRevision()`。
- [x] reload 行为
  - [x] 新 generation 按配置默认索引初始化。
  - [x] 运行时选择不跨 reload 保留。
- [x] 健康检查
  - [x] 一期可以不做选择组健康检查，`runtime.health` 返回 `[]`。
  - [ ] 如需延迟显示，显式 `ActivateCheck` 并导出 dialer 健康快照（需评估额外探测流量）。（一期未做）
- [x] 测试
  - [x] 默认成员。
  - [x] `select(1)` 初始成员。
  - [x] tcp/udp 独立切换。
  - [x] 越界索引错误。
  - [x] reload 后恢复默认。
  - [x] kernel optimistic alive 不回归。
- [x] 文档
  - [x] 中英文 README。
  - [x] `docs/*/configuration/separate-config.md`。

### P1-2 groups 资源

- [x] `GET /api/v1/groups`
  - [x] 返回 `GroupSummary[]`。
  - [x] 不包含 builtin `direct` / `block`，只列用户配置组。
- [x] `GET /api/v1/groups/{group_id}`
  - [x] 返回完整 `Group`。
- [x] `GET /api/v1/groups/{group_id}/config`
  - [x] 返回 `{policy, config}`。
  - [x] `ETag` 为带引号的 `config_revision`。
- [x] `PATCH /api/v1/groups/{group_id}/config`
  - [x] `config_patch=false`，返回 `404 capability_not_supported`。
- [x] `PUT /api/v1/groups/{group_id}/selection`
  - [x] 仅 `select` 组可用。
  - [x] `network` 支持 `tcp` / `udp` / `both`。
  - [x] 返回 `GroupSelectionResult`，`source: "runtime"`，`connections_interrupted: false`。
- [x] `DELETE /api/v1/groups/{group_id}/selection`
  - [x] `select` 组返回 `409 state_conflict`。
  - [x] 自动策略返回 `422 unsupported_value`（一期无 override）。
- [x] 稳定 ID
  - [x] 组 ID：`g_<sha256(name)[:12]>`。
  - [x] 节点 ID：`n_<sha256(link 或 name+address+protocol)[:12]>`。
- [x] `GroupConfig` 返回全部 7 个 key（可为 `null`）：
  - [x] `default_member_id`
  - [x] `final_outbound`
  - [x] `check_url`
  - [x] `check_interval`
  - [x] `tolerance`
  - [x] `idle_timeout`
  - [x] `interrupt_connections`
  - [x] dae 扩展放 `config["x-dae"]`：
    - [x] `check_addresses`
    - [x] `tcp_check_http_method`
    - [x] `udp_check_dns`
- [x] `GroupCapabilities` 五个字段都要有：
  - [x] `can_select`
  - [x] `can_override`
  - [x] `supports_nested_groups: false`
  - [x] `mutable_config: []`
  - [x] `probe_transports: []`
- [x] `Group.runtime.selection` 同时包含 `tcp` 和 `udp`：
  - [x] `select`：当前成员，`source: "runtime"`。
  - [x] `fixed`：固定成员，`source: "policy"`。
  - [x] `random` / `urltest`：一期 `null`。
- [x] `Group.runtime.health`
  - [x] 一期返回 `[]`。
- [x] `Group.icon`
  - [x] 返回 `null`。
- [x] 错误
  - [x] 未知 group → `404 resource_not_found`。
  - [x] 非直接成员 → `422 unsupported_value`。
  - [x] 非法 `network` → `400 invalid_request`。
  - [x] `select` 组 `DELETE` → `409 state_conflict`。

### P1-3 operations

- [x] `POST /api/v1/operations/reload`
- [x] `POST /api/v1/operations/suspend`
- [x] `POST /api/v1/operations/resume`
  - [x] 返回 `202` + `OperationAccepted`。
  - [x] `Location` 与 body `href` 一致。
  - [x] `Retry-After: 1`。
- [x] `GET /api/v1/operations/{operation_id}`
  - [x] 返回 queued / running / succeeded / failed。
- [x] 内存 operation store
  - [x] 有界，按 `retention_seconds` 清理。
  - [x] 未完成 operation 不淘汰。
  - [x] 未知/过期 ID → `404 resource_not_found`。
- [x] `Idempotency-Key`
  - [x] 仅 reload/suspend/resume 支持。
  - [x] 相同 key + 相同 body → 返回原 202 body。
  - [x] 相同 key + 不同 body → `409 idempotency_conflict`。
- [x] 接入 reloadManager
  - [x] reload → `queueReloadRequest({isSuspend:false})`。
  - [x] suspend → `isSuspend:true`。
  - [x] resume → `isSuspend:false`。
  - [x] 已有 reload 进行中 → `409 state_conflict`。
- [x] 结果
  - [x] reload 成功：`result.active_generation_id`、`result.datapath_generation_id`。
  - [x] suspend 成功：`result.runtime_state = "suspended"`。
  - [x] resume 成功：`result.runtime_state = "running"`。
  - [x] reload 失败：返回 `reload_rejected`（`details` 未填 `committed` / `stage`，reloadManager 不区分失败阶段）。
- [x] 更新 `runtime.last_reload`，signal reload 也记录。
- [x] 如果本期不做 operations（不适用：本期已实现 operations）：
  - [ ] `resources.operations.available = false`。
  - [ ] `resources.reload` / `suspend` / `resume` 不可用。
  - [x] 不能只暴露端点不实现。

### P1-4 traffic history

- [x] `GET /api/v1/runtime/traffic/history?window_seconds=&max_points=`
- [x] 复用 `SnapshotRuntimeStats.Samples`。
- [x] 默认值：`window_seconds=3600`、`max_points=180`。
- [x] 超出上限/非法值 → `400 invalid_request`，不要静默截断。
- [x] 样本字段：
  - [x] `sampled_at` RFC3339。
  - [x] `upload_bytes_per_second` / `download_bytes_per_second` 十进制字符串。
  - [x] `connections` 一期 `null`。
- [x] `sampled_every_seconds` 取返回采样点的实际间隔（记录器为 0.25s，抽稀后按实测间隔上报）。
- [x] 抽稀按契约"每 N 个取一个"原样保留采样，不聚合（此前取桶内最大值，会伪造记录器没测到的峰值）；history 只含已完成的 250ms 桶，进行中的瞬时桶只参与 1s 速率计算。
- [x] `observed_at` 用快照时间。

### P2 可选增强

- [x] `GET /api/v1/nodes`、`GET /nodes/{id}`
  - [x] `Node.id/name/protocol/subscription_tag/group_ids/health` 必填。
  - [x] `health` 返回真实探测观测（未探测的网络域省略，新进程为 `[]`）。
  - [x] `limit` 1–1000，`cursor` / `next_cursor`（cursor 绑定 generation，过期返回 `410 snapshot_expired`）。
  - [x] 列表来源为 generation 管理的全部 dialer（含未被任何组选中的节点，排除 builtin direct/block）；`group_id` 过滤；`provider_id` 在 P3-5 之后指向所属 provider（P2 阶段曾恒为 `null`）。
  - [x] 同一分享链接出现在多个订阅时按 node ID 合并（成员关系与健康取并集）；`member_count` 与实际唯一成员数一致。
  - [x] `nodes.can_manage = false`；`POST/DELETE /nodes` 返回 `404 capability_not_supported`。
- [x] 组健康 `runtime.health`
  - [x] 导出 dialer alive / latency / avg10 / movingAvg / observedAt。
  - [x] 映射 `HealthObservation`、`sorting_latency_ms`、`ranking`（`ranking` 恒为 `null`，dae 无评分模型）。
- [x] `can_override`（自动策略 pin 成员）
  - [x] `random` / `min` / `min_avg10` / `min_moving_avg` 的 `can_override = true`；`PUT` 设置 pin（`source: "override"`），`DELETE` 清除。
  - [x] pin 按 transport 独立、忽略 `excluded` 与探测健康、不改变 kernel 准入；reload 后重置。
  - [x] UDP 准入（新流与既有 endpoint）对已 pin 的 transport 不做健康拦截，避免 pin 到 data-UDP 域未就绪的成员后黑洞。

### P3 计划实现

P3-1 ~ P3-12 全部实现，端点清单见下方「P3 已实现」。顺序按"数据已在进程内、只缺投影"到"需要新增采集/流式通道"排列。

#### P3-1 `runtime/outbounds`

- [x] `GET /api/v1/runtime/outbounds` → `RuntimeOutbounds`。
- [x] 新增 per-outbound 计数器：当前只有全局 `RecordUploadTraffic` / `RecordDownloadTraffic`。
  - [x] `upload_bytes` / `download_bytes`：在 TCP relay 与 UDP 收发热路径按出站归属累加，复用现有 record 回调签名（绑定 outbound index 的闭包），避免每次写入查表。
  - [x] `total_connections` / `errors`：在 flow 建立与 dial 失败处累加。
  - [x] `active_connections`：flow 生命周期计数（establish +1 / finish -1）。
  - [x] `counter_since` 与进程启动/generation 激活对齐，reload 不重置（"retained across reloads"），仅进程重启或显式 reset 时变更。
- [x] `kind`：`builtin`（direct/block）、`group`（用户组）；`node` 未按成员聚合（计数器在出站层）。
- [x] 能力：`resources.runtime_outbounds = { available: true }`。
- [x] 计数器使用原子加法（每次 record 仅一次 `atomic.Uint64.Add`，与现有全局计数器同量级）；基准结论：无需每 CPU 分片。
- [x] 测试：单位计数、reload 后累计不回退、热路径记录归属。

#### P3-2 `runtime/memory*`

- [x] `GET /api/v1/runtime/memory`：进程 RSS（`/proc/self/status`）+ cgroup v2（`memory.current` / `memory.max` / `memory.events`）+ eBPF memlock（`/proc/self/fdinfo`）。
- [x] `GET /api/v1/runtime/memory/history`：独立的有界 1s 采样环（3600 点），`window_seconds` 上限与 `traffic_history` 一致，抽稀规则相同。
- [x] 能力：`resources.runtime_memory = { available: true, metrics: [...] }`、`resources.memory_history = { available: true, max_window_seconds: 3600, max_points: 180 }`。
- [x] 测试：字段类型（十进制字符串）、cgroup scope、缺失文件降级为 `null`、history 窗口与抽稀。

#### P3-3 `datapath`

- [x] `GET /api/v1/datapath` → `Datapath`（`kind`/`state`/`visibility`/`ebpf`）。
- [x] `ebpf` 明细：map 占用（`EbpfMaps`/`MapOccupancy`，`conn_state_map` 批量扫描）、TC attachment、routing generation/epoch（已有 `ControlPlane.DatapathGenerationID()`）。
- [x] `visibility` 保持 `partial`（userspace 视图），不要声称 full transparency。
- [x] 能力：`resources.datapath = { available: true, kinds: [ebpf], details: [attachments, maps] }`。
- [x] 测试：无 BPF 时的降级状态、attachment scope 映射、map 缺失时 occupancy 为 `null`；`/api/v1/runtime` 的 `datapath.ebpf` 摘要与详细端点同源。

#### P3-4 `rules`

- [x] `GET /api/v1/rules`：导出已编译的 routing 规则（含 `routing.Rule` 的匹配集合与出站）。契约规定该资源不分页（`max_rules` 保证整个字典一次返回）。
- [x] 需要新的只读导出视图（当前 `routingMatcher` 只保留匹配结构，不回显原始规则文本）。
- [x] 能力：`resources.rules = { available: true, max_page_size }`。
- [x] 测试：规则条目与 `dae validate` 的语义一致；敏感字段（节点 link）不泄漏。

#### P3-5 `providers*`

- [x] `GET /api/v1/providers`、`GET /api/v1/providers/{provider_id}`：把 `subscription` / `node` section 投影为 provider（`subscription_tag` 即 provider 身份；`node_ids` 用稳定的 `n_` ID）。
- [x] `POST /api/v1/providers/{provider_id}/refresh`：依赖 operations + 写配置（当前不做配置写入）→ 先只读；`can_refresh = false`。
- [x] 节点资源补 `provider_id`（P2 里恒为 `null`）：改为内联 `node` section 的 provider id 或订阅 tag。
- [x] 能力：`resources.providers = { available: true, can_refresh: false, can_manage: false, max_page_size }`。
- [x] 测试：provider 身份与 `Node.subscription_tag` 对应；未知 provider → `404 resource_not_found`。

#### P3-6 `geodata`

- [x] `GET /api/v1/geodata`：`externGeoDataDirs` + `geosite.dat` / `geoip.dat` 的读取状态、版本、校验和。
- [x] `POST /api/v1/geodata/update`：需要写文件 + operations；首期不做（`can_update = false`）。
- [x] 能力：`resources.geodata = { available: true, can_update: false, assets: [geoip, geosite] }`。
- [x] 测试：缺失资产时为 `assets: []` 而不是启动失败。

#### P3-7 `dns/*`

- [x] `GET /api/v1/dns/cache`、`DELETE /api/v1/dns/cache/{entry_id}`、`POST /api/v1/dns/cache/flush`：需要 daedns 暴露缓存枚举与删除（当前只有 flush/统计）。
- [x] `GET /api/v1/dns/log`、`GET /api/v1/dns/rules`、`POST /api/v1/dns/query`：
  - [x] `dns/log` 需要新增有界环形日志（记录 qname/qtype/upstream/耗时），默认关闭或小容量；
  - [x] `dns/rules` 是 `dns.routing` 的只读导出；
  - [x] `dns/query` 是一次性主动查询，需限流并标记为观测用途。
- [x] 能力：`dns_cache` / `dns_log` / `dns_rules` / `dns_query` 分别声明；`dns_log.max_records`、`dns_rules.max_rules` 取真实容量。
- [x] 测试：缓存条目 ID 稳定；flush 为幂等；`dns/log` 不记录诊断 `/dns/query` 调用。

#### P3-8 `connections*`

- [x] `GET /api/v1/connections`：从 `SessionManager` 导出活跃 flow（`ConnectionId`、五元组、outbound、sniffed domain、耗时、字节）。
- [x] `DELETE /api/v1/connections/{connection_id}`：关闭单条 flow（`force`/`interrupt` 语义），需要 session manager 支持按 ID 定位与关闭。
- [x] 能力：`resources.connections = { available: true, can_close: true, max_page_size }`。
- [x] 测试：`limit` 截断时报 `truncated` 且 `total_*` 仍为截断前匹配数；`src` 必须是 IP 字面量。

#### P3-9 `flows*`

- [x] `GET /api/v1/flows`、`GET /api/v1/flows/{flow_id}`：flow 需要有界历史存储（当前只有活跃 session），字段含 outbound 与字节数。规则命中路径依赖逐 flow trace，当前 `trace` 报 `disabled` + `missing: [not_instrumented]`。
- [x] 与 `connections` 的分工：`flows` 是短期历史（含已关闭），`connections` 是当前快照。
- [x] 能力：`resources.flows = { available: true, max_page_size, retention_seconds }`。
- [x] 测试：终态 flow 仍可查询；过期返回 `410 flow_expired`。

#### P3-10 `events`

- [x] `GET /api/v1/events`：事件流（SSE 或长轮询），`Last-Event-ID` 恢复，事件类型覆盖 `generation.changed`、flow/connection 终态、operation 完成。
- [x] 需要新的进程内事件总线 + 有界 replay（`event_cursor_expired` 语义）。
- [x] 与 operations 复用同一事件源，避免两套状态机。
- [x] 能力：`resources.events = { available: true, kinds, retention_seconds, max_buffered_events, max_clients, heartbeat_seconds }`。
- [x] 测试：断线重连不丢事件、不重复；未知/过期 Last-Event-ID → `409 event_cursor_expired`（契约用 409，不是 410，避免与分页游标混淆）。

#### P3-11 `logs`

- [x] `GET /api/v1/logs`：把 logrus 输出接入有界 ring / SSE 流，支持 `level`、`target` 过滤与 `Last-Event-ID` 续传。
- [x] 安全：沿用 P0 规则，不记录 `Authorization`、secret 与查询串；日志条目需结构化字段而非自由文本。
- [x] 能力：`resources.logs = { available: true, max_page_size, retention_seconds }`。
- [x] 测试：ring 满时不阻塞业务线程；跨 reload 保留；日志内容不含凭证。

#### P3-12 `probes`

- [x] `POST /api/v1/probes`：对 node / group 发起一次受控探测，返回 `202` + operation（复用 P1-3 的 operation store）。
- [x] 需要探测执行器（通过节点自己的 dialer 发起用户态拨号，支持 tcp/udp、ip_version、超时上限）与并发/速率限制。
- [x] `result` 映射 `ProbeResult`（`results[]` 含 `member_id`、`transport`、`latency_ms`、`state`、`error`）。
- [x] 能力：`resources.probes = { available: true, targets: [node, group], kinds, transports, ip_versions, limits }`。
- [x] 测试：并发探测限流；探测不改变 selection（除显式 `selection_changed`）；超时返回结构化错误。

#### P3 通用约束

- [x] 每个资源先加 provider 接口 + `capabilities` 声明，再接实现：`available: false` 时端点必须返回 `404 capability_not_supported`（不能只暴露端点不实现）。
- [x] 分页/游标统一语义（`limit` 1–1000、cursor 绑定快照、过期 `410 snapshot_expired`）。
- [x] 所有新增写路径（flush/close/refresh/update/query）都要幂等键或明确非幂等说明，并评估是否需要 operation。
- [x] 隐私与体积：`logs` / `dns/log` / `flows` 需要容量上限与脱敏规则后再开放。

## 4. 端点清单

### 实现

| Method | Path | 说明 |
|---|---|---|
| GET | `/api` | discovery |
| GET | `/api/v1/version` | 版本 |
| GET | `/api/v1/capabilities` | 能力声明 |
| GET | `/api/v1/runtime` | 运行时状态 |
| GET | `/api/v1/runtime/traffic/history` | 流量历史 |
| GET | `/api/v1/groups` | 组列表 |
| GET | `/api/v1/groups/{group_id}` | 组详情 |
| GET | `/api/v1/groups/{group_id}/config` | 组配置（只读） |
| PUT | `/api/v1/groups/{group_id}/selection` | 运行时选择（`select`）或 pin（自动策略） |
| DELETE | `/api/v1/groups/{group_id}/selection` | 清除 pin；`select` 返回 409，`fixed` 返回 422 |
| POST | `/api/v1/operations/reload` | 异步 reload |
| POST | `/api/v1/operations/suspend` | 异步 suspend |
| POST | `/api/v1/operations/resume` | 异步 resume |
| GET | `/api/v1/operations/{operation_id}` | operation 状态 |
| GET | `/api/v1/nodes` | 节点列表（`group_id` / `limit` / `cursor`） |
| GET | `/api/v1/nodes/{node_id}` | 节点详情 |
| GET | `/api/v1/runtime/outbounds` | 按出站累计计数器（reload 保留） |
| GET | `/api/v1/runtime/memory` | 进程 / cgroup / eBPF 内存 |
| GET | `/api/v1/runtime/memory/history` | 内存历史 |
| GET | `/api/v1/datapath` | eBPF datapath 明细 |
| GET | `/ui` / `/ui/*` | 自托管前端（配置 `api.ui` 时）：静态、公开，无需认证 |
| GET | 其他任意路径（含 `/`） | 配置 `api.ui` 时 302 → `/ui/`；未配置时 404。**不会返回 401** |

> 路由边界：只有 `/api` 与 `/api/v1/...` 属于控制面并参与认证；其余路径一律视为页面访问。

### P3 已实现

以下端点均已接入；仅明确标注的子能力（providers 增删/refresh、geodata update）仍返回 `404 capability_not_supported`。

| Method | Path | 计划 | 依赖 |
|---|---|---|---|
| GET | `/api/v1/rules` | P3-4 | routing 规则只读导出 |
| GET | `/api/v1/providers` | P3-5 | `subscription`/`node` section 投影 |
| GET | `/api/v1/providers/{provider_id}` | P3-5 | 同上 |
| POST | `/api/v1/providers/{provider_id}/refresh` | P3-5 | 需配置写入 + operations（首期 `can_refresh=false`） |
| GET | `/api/v1/geodata` | P3-6 | geodata 资产状态 |
| POST | `/api/v1/geodata/update` | P3-6 | 写文件 + operations（首期 `can_update=false`） |
| GET | `/api/v1/dns/cache` | P3-7 | daedns 缓存枚举 |
| DELETE | `/api/v1/dns/cache/{entry_id}` | P3-7 | 单条删除 |
| POST | `/api/v1/dns/cache/flush` | P3-7 | 已有 flush |
| GET | `/api/v1/dns/log` | P3-7 | 新增有界 DNS 日志 |
| GET | `/api/v1/dns/rules` | P3-7 | `dns.routing` 只读导出 |
| POST | `/api/v1/dns/query` | P3-7 | 主动查询 + 限流 |
| GET | `/api/v1/connections` | P3-8 | SessionManager 活跃 flow 导出 |
| DELETE | `/api/v1/connections/{connection_id}` | P3-8 | 按 ID 关闭 flow |
| GET | `/api/v1/flows` | P3-9 | flow 有界历史 |
| GET | `/api/v1/flows/{flow_id}` | P3-9 | 同上 |
| GET | `/api/v1/events` | P3-10 | 事件总线 + replay |
| GET | `/api/v1/logs` | P3-11 | 日志 ring / 流式通道 |
| POST | `/api/v1/probes` | P3-12 | 探测执行器 + operations |

> `/api/v1/routing/trace` 未列入 P3（需要按 flow 记录规则命中路径），当前返回 `404 capability_not_supported`，归入下方的"不在路线图内"。

实现要点（契约对齐）：

- 分页：`nodes` / `providers` 的 cursor 绑定 generation，reload 后旧 cursor 返回 `410 snapshot_expired`；`dns/cache`、`dns/log`、`flows` 使用不透明 cursor（base64 JSON，含 walk 类型、过滤条件指纹、limit、5 分钟有效期），过滤条件或 limit 不一致同样返回 `410 snapshot_expired`。
- 限额：`limit` 统一 1–1000（默认 100，`dns/log` 默认 200 且上限为 `dns_log.max_page_size`），越界返回 `400 invalid_request`；`connections` 按 limit 截断并置 `truncated`，`total_tcp` / `total_udp` 保持截断前的匹配数。
- 限流：`dns/query` 60 次/分钟；`probes` 同时运行 4 个、排队 16 个、120 次/分钟。超限分别返回 `429 rate_limited` / `503 temporarily_unavailable`，并带 `Retry-After`。
- 只读定位：`providers` 的增删/refresh、`geodata/update`、`config*`、`nodes` 写操作全部 `404 capability_not_supported`。

### 声明不可用（不在路线图内）

以下已知契约资源没有实现计划，统一返回 `404 capability_not_supported`（不落入普通
`404 resource_not_found`）：

- `/api/v1/config*`（含 `/config/validate`、`/config/sources*`）
- `/api/v1/runtime/settings`
- `/api/v1/routing/trace`
- `/api/v1/auth`、`/api/v1/auth/*`（只做 token mode）
- `PATCH /api/v1/groups/{group_id}/config`
- `POST /api/v1/nodes`、`DELETE /api/v1/nodes/{node_id}`（`nodes.can_manage = false`）

## 5. 契约易踩点

1. **`AdmittedDiscovery.links` 要求全部固定链接**，即使资源不可用也要返回。
2. **`GroupConfig` 的 7 个 key 全部必填**，可为 `null`。
3. **`GroupCapabilities` 五个字段全部必填**，包括 `mutable_config` 和 `probe_transports`。
4. **`GroupSummary.selection` 要求 `tcp_member_id` 和 `udp_member_id`**。
5. **`Group.runtime.selection` 要求 `tcp` 和 `udp`**。
6. **uint64 必须是十进制字符串**，bounded count/limit 才是 JSON number。
7. **`ErrorResponse` 必须有 `request_id`**（可为 `null`）。
8. **不可用资源返回 `404 capability_not_supported`**。
9. **`PATCH /groups/{id}/config` 在 `config_patch=false` 时返回 404 capability_not_supported**，不能 405。
10. **`DELETE /groups/{id}/selection` 对 selector 返回 `409 state_conflict`**。
11. **`PUT /groups/{id}/selection` 对无 `can_select` / `can_override` 的策略返回 `422 unsupported_value`**。
12. **不要声明 `full_transparency`**。
13. **组/节点 ID 必须稳定**，不能从 name 直接推导，也不能 reload 后随机变化。
14. **认证模式**：非 loopback 必须有 `secret`（token mode）；secretless 匿名仅限 loopback 且显式 `allow_anonymous_loopback: true`。TLS 是部署要求（listener 或受信任本机反向代理），不是 dae 配置校验项。

## 6. 测试与 CI

- [x] 配置测试
  - [x] `api` section 解析、默认值、`enabled:false` 不启动。
  - [x] 非 loopback 无 secret 校验失败。
  - [x] `secret` 为空且 `allow_anonymous_loopback=false` 校验失败。
  - [x] `secret` 为空 + `allow_anonymous_loopback=true` 且 listener 非 loopback 校验失败。
  - [x] `secret` 非空时 loopback / 非 loopback 都必须 Bearer。
  - [x] `dae validate -c` 覆盖 API 配置。
- [x] `select` 组单测
  - [x] 默认/指定索引。
  - [x] tcp/udp 独立切换。
  - [x] 越界索引。
  - [x] reload 重置。
  - [x] `groupPublishesOptimisticAlive` 包含 `select`。
- [x] handler 单测（`httptest` + fake provider）
  - [x] discovery public/full view。
  - [x] 401 / 403 / 404 capability / 405。
  - [x] 409 / 422（随 P1 端点补）。
  - [x] CORS 预检、Host/Origin、`Sec-Fetch-Site`。
  - [x] body/header/target 限制。
  - [x] uint64 十进制字符串、`Cache-Control` / `nosniff`。
  - [x] 自托管前端：`/ui/` 公开、非 `/api` 路径 302（绝不 401）、无 UI 时 404、缺 `index.html` 仅 warning 且 API 可用。
  - [ ] RFC3339 时间戳格式断言。
- [ ] 契约测试
  - [ ] 将 `api-standardize/source/openapi.yaml` 固定到 `testdata/`（或 CI 拉取固定 commit）。
  - [ ] 用 JSON Schema 校验每个 handler 的响应和错误 body。
  - [ ] 覆盖 base、groups、selection、operations、traffic history。
  - [x] 手工校验（一次性）：用 `honk` 分支的 `source/openapi.yaml` + ajv 校验真实 handler 输出 13/13 通过（`GroupList`、`Group`、`GroupConfigDocument`、`Capabilities`、`TrafficHistory`、`Operation`（queued/running/failed/succeeded）、`OperationAccepted`、`GroupSelectionResult`、`GroupSelectionRequest`、`ErrorResponse`）。自动化契约测试仍未接入。
- [ ] 集成测试
  - [ ] loopback + 无 secret 启动 API。
  - [ ] discovery → capabilities → runtime → groups → selection → reload。
- [x] CI
  - [x] `gofmt`
  - [x] `go vet`
  - [x] `go test ./...`（`go test -tags dae_stub_ebpf ./...` 本地通过）

## 7. 文档

- [x] `docs/en/configuration/api.md`
- [x] `docs/zh/configuration/api.md`
- [x] 中英文 README 配置示例增加 `api` section。
- [x] 组策略文档增加 `select`，说明“运行时选择不落盘、reload 重置”。
- [x] `CHANGELOGS.md`。
- [ ] 确认 dae-wing 等外部消费者能容忍新增 `api` section；`api.enabled=false` 时行为不变。
- [x] 明确非 loopback 必须 `secret`，且所有非 discovery 请求带 `Authorization: Bearer`；TLS 由受信任反向代理终止，dae 不提供 TLS listener。

## 8. 实施顺序

1. 配置 + API server 骨架 + 认证/错误/中间件
2. discovery / version / capabilities / runtime
3. `select` 组策略 + groups 资源 + selection 端点
4. operations（reload/suspend/resume）+ traffic history
5. nodes / group health / can_override
6. P3：runtime/outbounds → runtime/memory* → datapath → rules → providers → geodata →
   dns/* → connections* → flows* → events → logs → probes（每项先 provider 接口 + capability）
7. 契约测试 + 文档 + CHANGELOG

## 9. 验收标准

- [x] `dae validate -c` 对合法 `api` 配置通过，对非法配置给出明确错误。
- [x] `api.enabled=false` 时完全不监听端口。
- [x] secretless loopback 必须显式 `allow_anonymous_loopback: true` 才能匿名；否则启动失败。
- [x] 非 loopback 无 secret 启动失败；非 loopback + secret 时所有非 discovery 请求必须带 `Authorization: Bearer`。
- [x] `secret` 非空时 loopback 请求也必须 Bearer。
- [x] TLS 不在 dae 配置中强制；文档要求非 loopback 部署在受信任 TLS 反向代理后。
- [x] `GET /api`、`/api/v1/version`、`/api/v1/capabilities`、`/api/v1/runtime` 通过契约 schema 校验。（已用 origin/honk HEAD 与 doona pin 的两份契约手工校验 16/16 通过）
- [x] `GET /api/v1/version` 的 `engine.version` 与 `dae -v` 完全一致，`build` 带 `revision`/`target`/`built_at`（未知为 `null`）。
- [x] `/ui/`（配置 `api.ui` 时）无需任何认证即可加载；`/api` discovery 公开，`/api/v1/*` 在 token 模式返回 `401`。
- [x] 任意非 `/api` 路径（含 `/`、深链、拼错路径）302 → `/ui/`，不会返回 `401`；未配置 `ui` 时返回 `404`。
- [x] UI 目录缺失或缺 `index.html` 时只打 warning 且 `/ui/` 返回 `404`，进程、API 与代理照常运行。
- [x] 访问日志：成功请求 `debug`、拒绝 `info`（带 `error_code`）、`5xx` `error`，每 60s 一行 `Native API traffic` 汇总；不记录请求头与查询串。
- [x] `GET /api/v1/groups`、`/groups/{id}`、`/groups/{id}/config` 通过契约 schema 校验。（用 `honk` 契约 + ajv 对真实 handler 输出手工校验通过；自动化契约测试未接入）
- [x] `select` 组可通过 `PUT /selection` 按 tcp/udp 切换成员，reload 后恢复配置默认。
- [x] `DELETE /selection` 对 selector 返回 `409 state_conflict`。
- [x] `PATCH /groups/{id}/config` 返回 `404 capability_not_supported`。
- [x] reload/suspend/resume 返回 202，operation 可轮询到 succeeded/failed。
- [x] `traffic_history` 校验 `window_seconds` / `max_points` 上限，非法值返回 400。
- [x] 所有错误响应包含 `error.code`、`error.message`、`request_id`。（应用层错误均带；>12288B 头部由 net/http 直接回 431 纯文本）
- [x] 所有响应带 `Cache-Control: no-store` 和 `X-Content-Type-Options: nosniff`。
