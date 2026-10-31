# Native API

dae can expose a native HTTP control-plane API compatible with the
[api-standardize](https://github.com/daeuniverse/api-standardize) contract. The
listener is **disabled by default**.

## Configuration

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

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Start the native listener. |
| `listen` | `127.0.0.1:9527` | Numeric IP and port. Hostnames and the `:port` shorthand are rejected. |
| `secret` | empty | Non-empty selects token mode. Every non-discovery request must send `Authorization: Bearer <secret>`. |
| `allow_anonymous_loopback` | `false` | Allow credential-free requests only when `secret` is empty and the listener is bound to loopback. |
| `allow_origins` | empty | Exact HTTP(S) origins allowed for cross-origin browser access. |
| `allowed_hosts` | empty | Additional Host authorities accepted by the listener. Omitted port means 80. |
| `ui` | empty | Absolute directory holding a built frontend. Served at `/ui/` without credentials; other non-`/api` paths redirect there. Empty disables UI hosting. |

## Authentication

Choose one mode:

- **Token mode**: set a non-empty `secret`. All requests except `GET /api`
  (discovery) require `Authorization: Bearer <secret>`.
- **Anonymous loopback**: leave `secret` empty, set
  `allow_anonymous_loopback: true`, and bind to a loopback address.

An enabled listener with neither mode fails validation. A non-loopback listener
requires `secret`; `allow_anonymous_loopback` cannot replace it.

Contract-aware browsers (such as doona) pick their sign-in screen from the public
discovery view, whose `auth.mode` has no "no authentication" value. With
anonymous loopback they therefore still ask for a token: enter any placeholder.
When no `secret` is set, the listener ignores `Authorization` on non-discovery
requests and admits the loopback caller anyway.

Use an unpredictable token of at least 16 bytes. The secret must be visible
ASCII without whitespace or commas. Secrets are never returned by the API or
written to logs.

`GET /api` is public in every mode. Without a credential it returns the public
discovery view; with a valid token it returns the full view. In token mode,
`/api/v1/version` and `/api/v1/capabilities` also require the token.

### Local machine without a token

```dae
api {
    enabled: true
    listen: '127.0.0.1:9527'
    allow_anonymous_loopback: true
}
```

With `secret` empty and a loopback listener, requests from this machine need no
`Authorization` header at all. The contract permits anonymous access only on an
explicitly secretless listener, so a listener that also serves other hosts must
set `secret`, and then every request carries the token, loopback included.

## TLS

dae serves plain HTTP and does not terminate TLS. When listening on a
non-loopback address, terminate TLS at a trusted reverse proxy and do not expose
the listener directly to an untrusted network. dae logs a startup warning for
non-loopback listeners; TLS is a deployment requirement, not a configuration
validation that rejects the listener.

## Host and Origin checks

- The `Host` header must name the configured listening authority. Loopback
  listeners also accept `localhost`, `127.0.0.1` and `[::1]` at the listening
  port. A wildcard bind accepts IP-literal hosts and `localhost`; DNS names need
  `allowed_hosts`.
- Cross-origin browser access needs the exact origin in `allow_origins`.
- A secretless loopback listener rejects `Sec-Fetch-Site: cross-site` requests.
- Forwarded headers are not trusted as authorization.

## Endpoints

Current implementation:

- `GET /api` — discovery
- `GET /api/v1/version`
- `GET /api/v1/capabilities`
- `GET /api/v1/runtime`
- `GET /api/v1/runtime/traffic/history?window_seconds=&max_points=`
- `GET /api/v1/runtime/outbounds` — per-outbound counters, retained across reloads
- `GET /api/v1/runtime/memory` — process, cgroup v2 and eBPF memory
- `GET /api/v1/runtime/memory/history?window_seconds=&max_points=`
- `GET /api/v1/datapath` — eBPF attachments, routing generation and map occupancy
- `GET /api/v1/groups`
- `GET /api/v1/groups/{group_id}`
- `GET /api/v1/groups/{group_id}/config` (read-only, `ETag` is the config revision)
- `PUT /api/v1/groups/{group_id}/selection` — switch a `select` group member, or
  pin one on an automatic policy
- `DELETE /api/v1/groups/{group_id}/selection` — drop the pin; a selector answers
  `409 state_conflict`, and `fixed` answers `422 unsupported_value`
- `GET /api/v1/nodes?group_id=&limit=&cursor=`
- `GET /api/v1/nodes/{node_id}`
- `POST /api/v1/operations/reload`
- `POST /api/v1/operations/suspend`
- `POST /api/v1/operations/resume`
- `GET /api/v1/operations/{operation_id}`
- `GET /api/v1/rules` — active routing rules of the running generation
- `GET /api/v1/providers` and `GET /api/v1/providers/{provider_id}`
- `GET /api/v1/geodata` — geoip/geosite asset fingerprints
- `GET /api/v1/dns/cache`, `DELETE /api/v1/dns/cache?name=`,
  `DELETE /api/v1/dns/cache/{entry_id}`, `POST /api/v1/dns/cache/flush`
- `GET /api/v1/dns/log`, `GET /api/v1/dns/rules`, `POST /api/v1/dns/query`
- `GET /api/v1/connections`, `DELETE /api/v1/connections/{connection_id}`,
  `DELETE /api/v1/connections?all=true`
- `GET /api/v1/flows`, `GET /api/v1/flows/{flow_id}`
- `GET /api/v1/events` and `GET /api/v1/logs` — server-sent event streams
- `POST /api/v1/probes` — start a node or group probe; the operation is polled
  through `GET /api/v1/operations/{operation_id}`

`POST /api/v1/providers` (inline provider creation),
`DELETE /api/v1/providers/{provider_id}`, `POST
/api/v1/providers/{provider_id}/refresh` and `POST /api/v1/geodata/update`
answer `404 capability_not_supported`, matching `providers.can_refresh`,
`providers.can_manage` and `geodata.can_update` being `false`: dae never writes
configuration or re-downloads assets through the API.
`PATCH /api/v1/groups/{group_id}/config`, `POST /api/v1/nodes` and
`DELETE /api/v1/nodes/{node_id}` answer the same code for the same reason
(`nodes.can_manage = false`).

`/api/v1/config*`, `/api/v1/runtime/settings`, `/api/v1/routing/trace` and
`/api/v1/auth*` remain unimplemented, so a frontend that edits configuration in
place (for example the routing and DNS editors of a lite doona build) cannot use
those screens against dae; rules and DNS rules are read-only views here.

### Groups and selection

Group and member identifiers are stable across reloads: `g_` and `n_` followed
by a hash of the group name or of the node link. A member is reported as
`kind: "node"`.

`policy.kind` follows the dae policy: `select` is `selector`, `fixed` is
`fixed`, `random` is `random`, and `min` / `min_avg10` / `min_moving_avg` are
`urltest`. A `selector` accepts `PUT .../selection`; the automatic policies
(`random` and the three `min*` policies) accept the same call as a runtime pin
(`can_override: true`), and `fixed` accepts nothing:

```bash
curl -X PUT -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' \
  -d '{"member_id":"n_18f2c6a4b311","network":"both"}' \
  http://127.0.0.1:9527/api/v1/groups/g_5f2c1d7a8e04/selection
```

`network` is `tcp`, `udp` or `both`; TCP and UDP choices are independent. A
selector reports `source: "runtime"`, a pin on an automatic policy reports
`source: "override"`. Both live in memory only: neither is written back to the
configuration, and the next reload (or a restart) returns to the configured
behaviour.

A pinned member outranks the automatic policy for that transport and ignores
probe health, exactly like a selector; UDP admission does not drop a pinned
member because its data-UDP probe domain is cold. The pin does not change
kernel admission:
if every member of an automatic group is unhealthy the kernel still rejects the
group, so pin a member you know is reachable. `DELETE .../selection` clears the
pin and the policy chooses again; the response reports `{tcp: null, udp: null}`
because an automatic policy has no stable selection to name.

`config` always carries the seven contract keys, `null` when the group sets no
value of its own, plus `x-dae` with dae's own `check_addresses`,
`tcp_check_http_method` and `udp_check_dns`.

`runtime.health` lists one entry per probed member and network domain (TCP,
DNS-UDP, data-UDP) with `state`, `latency_ms`, `moving_avg_ms`, `avg10_ms`,
`observed_at`, and the metric the group sorts by in `sorting_latency_ms`
(last latency for `min`, the 10-sample average for `min_avg10`, the moving
average for `min_moving_avg`, `null` for `random`). A collection that was never
probed is omitted rather than reported with a fabricated timestamp, so a fresh
process answers `[]`. `warmth` is `unknown` and `ranking` is `null` because dae
does not track either.

### Nodes

`GET /api/v1/nodes` lists every dialer the generation manages, including nodes
no group currently selects; `group_id` narrows the list to one group's members
(an unknown group is `404 resource_not_found`). IDs are the same stable `n_`
identifiers the group members use, so a node keeps its ID across reloads as long
as its share link is unchanged.

`limit` is 1–1000 (default 100). `cursor` is opaque and bound to one generation:
reusing a cursor after a reload answers `410 snapshot_expired`, which means
"start the walk again". `next_cursor` is `null` on the last page.

Two subscriptions that carry the same share link are one node — the ID is
derived from the link — so the list reports it once and merges its memberships
and health samples. A group reports such duplicates as one member as well.

`health` is the same projection groups report, keyed by transport, purpose and
IP version. `subscription_tag` carries the subscription the node came from and
is `null` for inline nodes; `provider_id` names the provider that owns the node
(see below). Node management (`POST`, `DELETE`) is `404
capability_not_supported`.

### Rules, providers and geodata

`GET /api/v1/rules` returns the running routing generation's rule dictionary in
evaluation order, including the fallback entry. `rule_id` is `traffic:<index>`
for a configured rule and `traffic:fallback` for the fallback, the same
identifier `FlowSummary.rule_id` and a routing trace use. Join rules by
`generation_id` and `rule_id`, never by expression or index alone, and refetch
after `generation.changed`. The resource never paginates: `max_rules` is the
routing dictionary capacity (1<<20), so the complete dictionary always fits in
one response and there is no `410 snapshot_expired` for it.

`GET /api/v1/providers` groups the node inventory by subscription tag. The node
section and untagged subscriptions form the editable `inline` provider
(`p_inline`); every other tag becomes `p_` plus a hash of the tag, so a
provider ID (and its nodes' `provider_id`) survives a reload as long as the tag
does. `node_count` comes from the running generation, and a provider whose
subscription produced no dialer reports `status: "stale"` instead of an
invented update time. Pagination reuses the generation-bound node cursor.
`can_refresh` and `can_manage` are `false`, so `POST /api/v1/providers`,
`DELETE /api/v1/providers/{provider_id}` and `POST
/api/v1/providers/{provider_id}/refresh` answer `404 capability_not_supported`.

`GET /api/v1/geodata` reports the geoip and geosite files dae loaded with size,
mtime and SHA-256. The digest is cached until the file changes, so polling is
cheap. `can_update` is `false`: assets come from the installation, and
`POST /api/v1/geodata/update` answers `404 capability_not_supported`.

### DNS cache, log, rules and query

The DNS resources inspect the live resolver, so they exist only while a DNS
controller is running; otherwise they answer `503 temporarily_unavailable`.

`GET /api/v1/dns/cache` lists runtime entries with `name`, `domain`, `type`,
`include_expired`, `limit` (1–1000, default 100) and an opaque `cursor`. Entry
IDs are `de_` plus a hash of the cache key, which is the only stable handle: the
same ID can be used with `DELETE /api/v1/dns/cache/{entry_id}`.
`DELETE /api/v1/dns/cache?name=` narrows by `type`, and
`POST /api/v1/dns/cache/flush` empties the cache; both answer
`{matched, deleted}` because an entry can be replaced (or already gone)
between matching and deletion.

`GET /api/v1/dns/log` returns the bounded ring of client resolutions, newest
first, with `name`, `type`, `src`, `limit` (default 200, at most
`dns_log.max_page_size`) and a cursor. Diagnostic `/dns/query` calls are not
recorded. A cursor that names a record already evicted from the ring answers
`410 snapshot_expired`, so a walk restarts without one.

`GET /api/v1/dns/rules` is the read-only DNS rule dictionary (request and
response, each with its fallback) of the running generation. `POST
/api/v1/dns/query` resolves one name through the same routing and cache the
datapath uses: `cache_mode` is `normal` or `bypass`, `upstream` forces one
configured DNS upstream by name, answers carry `cached`, `upstream`,
`elapsed_ms` and the cache entry ID. Queries are limited to 60 per minute per
caller (`429 rate_limited` with `Retry-After`) and time out after 5 seconds.

### Connections and flows

`GET /api/v1/connections` lists live userspace flows; `visibility` is `partial`
because kernel-bypass traffic never enters userspace. `type` (tcp/udp/all),
`src` (an IP literal, not a host:port) and `limit` (default 100) filter the
list, `total_tcp` / `total_udp` count matches before the limit, and
`truncated` says whether the limit hid entries. `can_close` is `true`:
`DELETE /api/v1/connections/{connection_id}` closes one flow, and `DELETE
/api/v1/connections?type=…&src=…` closes a filtered set. The bulk call refuses
to run without a filter unless `all=true` is explicit, and closes at most
`max_bulk_close` (1000) flows per request.

`GET /api/v1/flows` reads the closed-flow history instead: a ring of 2048
entries retained for 900 seconds, newest first, filtered by `network`, `state`
and `connection_id`, with `limit` (default 100) and an opaque cursor. `GET
/api/v1/flows/{flow_id}` returns one entry and answers `410 flow_expired` once
it left the ring. Flow IDs are `f_` plus a hash of the endpoints and start time,
and connections reference the same ID through `flow_id`. Flow detail carries a
`trace`, which this engine reports as `disabled` with
`missing: ["not_instrumented"]`: the evidence a trace needs is not recorded.

### Event streams and logs

`GET /api/v1/events` and `GET /api/v1/logs` are server-sent event streams. Both
open with `stream.ready`, whose `id` is the resume cursor; a client that
reconnects with `Last-Event-ID` continues after that frame, and an unknown or
evicted cursor answers `409 event_cursor_expired` so the client drops it and
establishes a new baseline. A slow client is disconnected rather than allowed
to block the engine.

The event stream publishes `runtime.updated`, `operation.updated` and
`generation.changed`; records stay in the bounded ring for 300 seconds. The log
stream mirrors dae's own log at `trace`–`error`, and `target` narrows it to one
logger. Log fields whose key contains `secret`, `token`, `authorization`,
`password` or `cookie` are dropped, and bearer tokens and URL query strings are
redacted from message text, so the stream never becomes a credential leak. The
log ring holds 1024 records for 300 seconds.

### Probes

`POST /api/v1/probes` starts an asynchronous probe and answers `202` with
`Location` and `Retry-After: 1`, like the reload operations; the result arrives
through `GET /api/v1/operations/{operation_id}`. `kind` is `tcp_connect`,
`http` or `dns`, and `transport` is `tcp`, `udp` or both (`tcp_connect` and
`http` are TCP only, `dns` accepts either). A `node` target probes one node; a
`group` target probes the group's members, optionally narrowed by `members`
(`direct` and `leaves` select the group itself).

Each result reports `healthy` or `unavailable` with `latency_ms`, the transport
and IP version that answered, and the destination ID in `member_id`. Probes run
as userspace dials through the node's own dialer, so they measure the same path
the proxy takes rather than the host's direct route. Work is bounded: 4 probes
run at once, 16 wait in the queue (`503 temporarily_unavailable` with
`Retry-After` when both are full), callers are limited to 120 requests per
minute (`429 rate_limited`), a job expands at most 256 members into 512 results,
and a job stops after 30 seconds, so one oversized group cannot hold the queue
forever. These numbers are what `capabilities.probes.limits` advertises.

### Traffic history

`GET /api/v1/runtime/traffic/history` returns the recorder samples, oldest
first. `window_seconds` defaults to 3600 (max 3600) and `max_points` defaults to
180 (max 180); out-of-range or non-numeric values are `400 invalid_request`
rather than being silently clamped. `sampled_every_seconds` is the actual
spacing of the returned samples, which grows when the window is thinned to fit
`max_points`. Thinning keeps every Nth recorded sample verbatim (timestamps and
rates untouched) instead of averaging or taking a maximum, so the returned
series never invents a peak the recorder did not measure. `connections` is
`null`.

### Operations

`reload`, `suspend` and `resume` are asynchronous: each answers `202` with
`Location` and `Retry-After: 1`, and `GET /api/v1/operations/{operation_id}`
reports `queued`, `running`, `succeeded` or `failed`. A request while another
reload is in flight is `409 state_conflict`; its `details.operation_id` names
the rejected record. `Idempotency-Key` replays the original `202` body for the
same request and answers `409 idempotency_conflict` when the key is reused for a
different operation. Records live in memory for 3600 seconds; unfinished
operations are never evicted.

With `ui` configured, `/ui/` serves the frontend and every other non-`/api` path
redirects there, so only `/api` and `/api/v1/...` take part in authentication.

`GET /api/v1/version` reports the same version `dae -v` prints: the value the
build injects, or, for a plain `go build`/`go install`, the module or VCS
version. `build` carries `revision`, `target` and `built_at` from the Go build
information, with `null` for whatever the build does not know.

## Self-hosted UI

Set `ui` to an absolute directory holding a built frontend and dae serves it at
`<listen>/ui/`:

```dae
api {
    enabled: true
    listen: '127.0.0.1:9527'
    secret: 'replace-with-a-long-random-token'
    ui: '/usr/share/doona'
}
```

- Only `/api` and `/api/v1/...` are API routes; they authenticate as configured.
  Every other path is a navigation: `/` and `/ui` redirect to `/ui/`, and so does
  any other path, so a deep link or a typo never returns an authentication error.
- Only files inside that directory are served. Directory listings are disabled,
  and a missing asset such as `/ui/assets/app.js` is a real `404`, never HTML.
- Extensionless misses fall back to `index.html`, so a client-side router keeps
  working.
- Content under `assets/` is served immutable for a year; other files use
  `no-cache`.
- Static files are public, because a browser cannot attach a bearer token to
  `<script src>`. Every API call the frontend makes still needs the token, and
  the Host/Origin checks above still apply to the UI.
- The path must be absolute. A directory that is missing or has no `index.html`
  never stops dae: startup logs a warning and `/ui/` answers `404` until the
  directory is usable, so a broken UI cannot take the proxy down. Changing `ui`
  requires a restart, like the rest of the `api` section.
- A frontend built for this contract (for example
  [doona](https://github.com/Zakkaus/doona)) targets its own origin when it is
  served from `/ui/`, so the only thing left to enter is the token.

## Logging

The API writes to dae's normal log:

- **Every request** at `debug` with `method`, `route`, `status`, `elapsed_ms`,
  `request_id`, `remote_ip` and `bytes`. A dashboard polls every few seconds, so
  this stays off at the default `info` level.
- **Refusals and failures** immediately: `4xx` at `info`, `5xx` at `error`, each
  with the contract `error_code` (for example `authentication_required`,
  `permission_denied`, `capability_not_supported`).
- **A rolling summary** every 60 seconds while the listener is serving traffic:
  `Native API traffic` with `served`, `refused` and `window_seconds`.
- Listener start and stop.

Headers and query strings are never logged, so an `Authorization` token or the
configured secret cannot reach the log. Routes are logged as templates, so
probing arbitrary paths cannot inflate log volume.

## Reload behavior

All `api` fields are restart-required. A reload that changes them is rejected or
keeps the previous listener and logs a warning; the listener is never partially
recreated.

## Example

```bash
curl http://127.0.0.1:9527/api
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9527/api/v1/runtime
```
