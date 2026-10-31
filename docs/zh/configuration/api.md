# 原生 API

dae 可以提供与 [api-standardize](https://github.com/daeuniverse/api-standardize)
契约兼容的原生 HTTP 控制面。该 listener **默认关闭**。

本页只讲 listener 的配置与部署；端点行为与资源契约见
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

## reload 行为

`api` 的所有字段都是 restart-required。reload 检测到变化时会拒绝或保留旧 listener
并打印 warning，不会部分重建 listener。

## 示例

```bash
curl http://127.0.0.1:9527/api
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9527/api/v1/runtime
```
