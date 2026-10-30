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

Other contract resources return `404 capability_not_supported` until they are
implemented. Planned but not built yet: `providers`, `geodata`, `rules`,
`dns/*`, `connections`, `flows`, `events`, `logs`, `probes`,
`runtime/memory*`, `runtime/outbounds` and `datapath`. `PATCH /api/v1/groups/{group_id}/config`, `POST /api/v1/nodes` and
`DELETE /api/v1/nodes/{node_id}` always answer `404 capability_not_supported`,
because dae never writes configuration through the API (`nodes.can_manage =
false`).

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
is `null` for inline nodes; `provider_id` is always `null` because dae has no
providers resource. Node management (`POST`, `DELETE`) is `404
capability_not_supported`.

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
