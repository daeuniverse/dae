# Native API reference

Listener configuration, authentication, TLS, Host/Origin checks and
self-hosting the UI are covered in
[configuration/api.md](../configuration/api.md). This page documents the
endpoints and the resource contract dae implements.

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
- `GET /api/v1/runtime/direct-stats` — opt-in direct-traffic counters
- `GET /api/v1/datapath` — eBPF attachments, routing generation and map occupancy
- `GET /api/v1/groups`
- `GET /api/v1/groups/{group_id}`
- `GET /api/v1/groups/{group_id}/config` (read-only, `ETag` is the config revision)
- `PATCH /api/v1/groups/{group_id}/config` (gated on configuration writes)
- `PUT /api/v1/groups/{group_id}/selection` — switch a `select` group member, or
  pin one on an automatic policy
- `DELETE /api/v1/groups/{group_id}/selection` — drop the pin; a selector answers
  `409 state_conflict`, and `fixed` answers `422 unsupported_value`
- `GET /api/v1/nodes?group_id=&limit=&cursor=`
- `GET /api/v1/nodes/{node_id}`
- `PATCH /api/v1/nodes/{node_id}` — rename and/or relink an inline node (gated on configuration writes)
- `POST /api/v1/operations/reload`
- `POST /api/v1/operations/suspend`
- `POST /api/v1/operations/resume`
- `GET /api/v1/operations/{operation_id}`
- `GET /api/v1/rules` — configured routing rules of the running generation
- `POST /api/v1/routing/trace` — simulate routing against the running generation; `resolve: "none"` only
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
`DELETE /api/v1/providers/{provider_id}` and `POST /api/v1/geodata/update`
answer `404 capability_not_supported`, matching `providers.can_manage` and
`geodata.can_update` being `false`: dae does not create or delete subscriptions
through the API.

`POST /api/v1/nodes` and `DELETE /api/v1/nodes/{node_id}` are implemented,
gated on the configuration write switch: `nodes.can_manage` is true only with
`api.config_write` and the managed layout. Both queue a reload and answer `202`
with a `node_create` or `node_delete` operation; `DELETE` stays idempotent for an
unknown id (`200 {"deleted": 0}`).

`PATCH /api/v1/nodes/{node_id}` edits an inline node. The body is
`{"name"?: string, "link"?: string}`: an omitted field (or an explicit `null`)
keeps its current value and at least one must be set. It also queues a reload and
answers `202` with a `node_update` operation whose result is the node; a rename
keeps the node id, a new link produces a new one (the id is derived from the
dialer the engine parses the link into, which may normalize a plugin link).
Existence and ownership are resolved before the values are checked: an unknown id
is `404 resource_not_found` and a subscription or file node is
`404 capability_not_supported` even when the body carries an invalid link; a bad
name or link answers `422 unsupported_value` and a taken name `409 state_conflict`.
A relink whose link another inline entry or already loaded node uses is
`409 state_conflict` too, because the API identifies a node by its link and two
entries with one link collapse into a single node. A generation that is ahead of
the file (the line is gone) answers `409 state_conflict`; a keyless entry
(`node { 'ss://…' }`) has no name to address and cannot be edited through the API
— edit the file instead. A patch that repeats the node's current values writes
nothing, starts no reload and answers `200 {"updated": 0}`. This endpoint is a
dae extension: the contract (`api-standardize`) currently defines creation and
deletion only.

`POST /api/v1/providers/{provider_id}/refresh` does not depend on that switch:
`providers.can_refresh` only needs the operations adapter, so it is true whenever
the API runs. Only a `subscription` provider can be refreshed — an inline or file
provider answers `404 capability_not_supported` — and it queues a
`provider_refresh` operation.

`/api/v1/runtime/settings` and `/api/v1/auth*` answer
`404 capability_not_supported`. Routing trace availability follows the running
generation; when `routing_trace.available` is false, its endpoint answers the
same error. Trace is disabled when the generation exceeds 4096 rule steps. It simulates
routing only: it does not connect or perform DNS
queries, and currently supports `resolve: "none"` only; `resolve: "live"` answers
`422 unsupported_value`. Limits are 30 requests per principal per minute and
120 globally per minute; excess requests answer `429 rate_limited` with
`Retry-After`.

Configuration supports source-level editing plus restricted group-config
editing: `GET /api/v1/config`, `GET /api/v1/config/sources/{source_id}`,
`PUT /api/v1/config/sources/{source_id}` (requires `If-Match`) and
`POST /api/v1/config/validate`. A `sources[].id` is the contract's request-local
diagnostic label: it defaults to `source-N`, overrides the visible source with
that id when one exists (a dae extension), and otherwise validates as a
standalone candidate that is never written; only `path` names a file. A
syntax check of a rewritten node block under `id: "node"` therefore does not
answer `404`. A rename (through `PATCH /nodes/{id}` or the dashboard editor)
rewrites the node's own source only; group filters and rules in other sources
keep the old name until they are updated separately. The contract has no
`GET /api/v1/config/sources` list route: the source list comes from
`GET /api/v1/config`'s `sources[]`, and a non-`POST` request to the collection
path answers `405`. Writes are available only when `api.config_write = true` and
the config directory follows the managed layout (`config.dae` includes
`config.d/*.dae` and `api.dae`); otherwise they answer `403 permission_denied`
with `details.reason`, and nothing is written.

Group config patches use `application/json-patch+json` and require the strong
`If-Match` revision from the config `ETag`. Only `/config/check_interval`
(seconds) and `/config/tolerance` (milliseconds) are mutable. A successful
change queues a reload and answers `202` with a `group_update` operation;
`groups.config_patch` and each group's `capabilities.mutable_config` reflect
whether writes are currently available.

Deliberate deviations from the contract:

- `api.dae` is hidden. It is omitted from `sources[]`, and its id answers
  `404 resource_not_found`, the same as an unknown id. Capabilities report it in
  `x-dae.hidden_sources`.
- `config.dae` is read-only (`entry_source`). A replacement may not change the
  `api` section.
- `GET` reads the files on disk, not an accepted snapshot. Its `revision` is
  the same function of the configuration that `runtime.generation.config_revision`
  uses, so the two compare: they match while disk is what the engine loaded and
  differ once a write has not been reloaded yet.

Rules and DNS rules are edited by replacing their owning source (`routing.dae`,
`dns.dae`). The API does not offer row-level edits.

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
pin and the policy chooses again. The response names the member the policy now
picks with `source: "runtime"` — an automatic group always reports the member it
dials with — except `random`, which re-rolls for every connection and answers
`null`.

`config` always carries the seven contract keys, `null` when the group sets no
value of its own, plus `x-dae` with dae's own `check_addresses`,
`tcp_check_http_method` and `udp_check_dns`.

`runtime.health` lists one entry per member and network key — TCP, DNS-UDP and
data-UDP, each per IP version — with `state`, `latency_ms`, `moving_avg_ms`,
`avg10_ms` and `observed_at`. `purpose` names what the latency is used for, not
which probe produced it: TCP and data-UDP are `data`, DNS is `dns`.

`sorting_latency_ms` is the value the engine actually compares: the policy
metric plus the recovery penalty and the group's `add_latency` offset, which is
why it can differ from the metric fields beside it. `ranking` explains that
score with `metric`, `score`, `group_offset_ms`, `recovery_penalty_ms` and
`reason`, plus a 1-based `rank` and `delta_to_best_ms` against the best member of
the same key. `rank` is the instantaneous order, while the group's selection
carries the `check_tolerance` hysteresis, so the two may name different members
by design. Data-UDP has no probe of its own: the engine ranks it through the DNS
samples of the same dialer, and this projection mirrors that instead of dropping
the key. A collection that was never probed is omitted rather than reported with
a fabricated timestamp, so a fresh process answers `[]`. `warmth` is `unknown`,
because dae does not track it.

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
IP version — three purposes per IP version (`tcp`/`data`, `udp`/`dns`,
`udp`/`data`), so a fully probed node reports six entries. `subscription_tag`
carries the subscription the node came from and is `null` for inline nodes and
for nodes from an untagged subscription, which still report their own provider
through `provider_id`. Node management (`POST`, `DELETE`) is available when
`api.config_write` is set and the tree follows the managed layout; otherwise it
is `404 capability_not_supported`.

### Rules, providers and geodata

`GET /api/v1/rules` returns the rules as configured, including the fallback
entry. The optimizers that build the datapath rewrite selector names, expand
every `geosite`/`geoip` reference into its entries, and merge or inject rules of
their own; exporting that output would describe a rule set nobody wrote and can
reach megabytes for a single configured line. The resource therefore reports the
configuration form and stays in the kilobyte range.

`rule_id` is `traffic:<index>` for a configured rule and `traffic:fallback` for
the fallback. `index` follows the configuration order, not the kernel evaluation
order, because the optimizers may merge adjacent rules with the same outbound and
add sniff-punt lines. Join rules by `generation_id` and `rule_id`, never by
expression, and refetch after `generation.changed`. A consumer that needs the
evaluated rule (a routing trace, for example) must map indices separately. The
resource never paginates: `max_rules` is the routing dictionary capacity
(1<<20), so the complete dictionary always fits in one response and there is no
`410 snapshot_expired` for it.

`GET /api/v1/providers` groups the node inventory by subscription tag. The node
section and untagged subscriptions form the editable `inline` provider
(`p_inline`); every other tag becomes `p_` plus a hash of the tag, so a
provider ID (and its nodes' `provider_id`) survives a reload as long as the tag
does. `node_count` comes from the running generation, and a provider whose
subscription produced no dialer reports `status: "stale"` instead of an
invented update time. Pagination reuses the generation-bound node cursor.

`can_refresh` follows the operations adapter alone, so it is true for every
subscription, while `can_manage` stays `false` because providers are never
created or deleted over the API. `POST /api/v1/providers/{provider_id}/refresh`
therefore queues a `provider_refresh` operation for a subscription and answers
`404 capability_not_supported` for any other provider kind. A refresh refetches
the subscription; when the fetch fails, the last good nodes are kept so the
running generation is not cut, and the provider reports the failure instead of a
success: `status` is `"stale"`, `last_error` carries the reason, and `updated_at`
is the time of the last attempt.

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
`dns_log.max_page_size`) and a cursor. `name` is a substring match against the
record's question name, not an exact name or suffix. Diagnostic `/dns/query`
calls are not recorded. A cache hit is recorded with `cached: true` and no
`upstream`, because no upstream was contacted; only an upstream exchange names
one. A cursor that names a record already evicted from the ring answers
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

`upload_bytes` and `download_bytes` are only present for flows dae forwards in
userspace and counts; UDP flows and everything the datapath handles directly
leave them null. Nothing aggregated from these fields, such as a per-device or
per-domain traffic ranking, therefore covers the whole link, and dae does not
claim device-level totals. `api.disable_connection_bytes: true` drops the two
fields entirely, so a client showing such a ranking has no partial figure to
present; every other connection attribute is unaffected.

`GET /api/v1/flows` reads the closed-flow history instead: a ring of 2048
entries retained for 900 seconds, newest first, filtered by `network`, `state`
and `connection_id`, with `limit` (default 100) and an opaque cursor.
`connection_id` is an exact match over both the active snapshot and the closed
history, so filtering by the ID of a connection that is still open returns that
flow (with `state: "active"`) instead of an empty list. Like the
DNS log and cache walks, the cursor names the last record the client received
rather than an offset, so records arriving at the head of the list while a walk
is in progress cannot make a later page repeat or skip entries. An anchor that
has left the ring answers `410 snapshot_expired`. `GET
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
establishes a new baseline. A cursor is also bound to the instance that issued
it and to a position that is still retained: one from before a restart, or one
whose records the ring has since dropped, expires instead of silently resuming
and skipping invalidations. A slow client is disconnected rather than allowed
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

`warmth` is `cold`; the engine opens a fresh connection per probe and cannot
honour a reuse constraint, so `warm` answers `422 unsupported_value` instead of
returning mislabelled results. Each result reports `healthy` or `unavailable`
with `latency_ms`, the transport and IP version that answered, and the
destination ID in `member_id`; `warmth` is `unknown` because a new logical
stream does not prove whether the physical tunnel is cold or warm. Work that
never started (job deadline) is `state: "unknown"` with an error message and is
not evidence of an unhealthy node. `ip_version` applies to the check
destination too: a configured host is resolved through the requested family, and
a literal address of the other family is rejected. The `http` and `dns` probes
read `tcp_check_url` / `udp_check_dns` the same way the health checks do: the
first entry is the destination and the literals after it are address overrides,
so the probe dials the override that matches `ip_version` instead of letting a
resolver pick the address. Each kind measures what its name says:

- `tcp_connect` opens a TCP connection to the node's own server address, using
  the direct dialer rather than the node, so it reports whether that server
  accepts connections. An outbound with no server address (the builtin `direct`
  group) falls back to a dial through the node.
- `http` sends a real `GET` through the node and requires a response below 500.
- `dns` sends a real query through the node and requires a well-formed answer.

Probes run as userspace dials through the node's own dialer, so they measure the
same path the proxy takes rather than the host's direct route. Work is bounded: 4 probes
run at once, at most 4 run against one node at a time across all jobs, 16 wait in the queue (`503 temporarily_unavailable` with
`Retry-After` when both are full), callers are limited to 120 requests per
minute (`429 rate_limited`), a job expands at most 256 members into 512 results,
and a job stops after 30 seconds, so one oversized group cannot hold the queue
forever. A request whose expanded member × transport × family count exceeds 512
answers `413 request_too_large` before any probe runs instead of silently
dropping the remaining dimensions. These numbers are what `capabilities.probes.limits` advertises.

### Runtime summary and per-outbound counters

`GET /api/v1/runtime` reports `traffic.observed_by: "userspace"`: every byte in
`traffic.bytes` was counted by the userspace relay, so the figure is payload
bytes. Traffic the datapath forwards without userspace - a flow routed `direct`
in the kernel, or `must_direct` traffic that never reaches the relay - is **not**
counted, so the totals read lower than the real link speed on a direct-heavy
deployment. That is deliberate: direct traffic accounting is an opt-in API observer, so
only deployments that enable `api.direct_stats` pay its per-packet kernel cost.

Rates are produced by a sampler that runs once per second over the process
totals, so the forwarding path only performs one atomic add per record.

`process.cpu_percent` is the daemon's CPU usage over the latest one-second
sampling interval, as a percentage of **one** CPU: `100` means one core fully
busy and a multi-core host can report more. It is a delta, not a lifetime
average, so it is `null` until two samples exist; a reload restarts the interval
and briefly reports `null` again. `process.pid` is present only with
`detail=full`.

`traffic.counter_since` and `runtime/outbounds.counter_since` report the same
process-level boundary and both survive a reload. The traffic store is
process-lifetime, like the per-outbound registry, so flows that survive a reload
keep landing in the numbers `/runtime` reads: the totals and the rate do not
freeze at the handoff and do not restart at zero.

`GET /api/v1/runtime/outbounds` reports `active_connections`,
`total_connections`, `upload_bytes`, `download_bytes` and `errors` per outbound.
The builtin `direct` row covers the `must_direct` bytes that do reach userspace,
so `sum(outbounds)` tracks `runtime.traffic.bytes` except for DNS traffic, which
no outbound owns. With `api.direct_stats` on, that row additionally carries
kernel-direct link bytes, so the sum exceeds `runtime.traffic.bytes` by that
amount. The builtin `block` row is not exposed: blocked traffic is dropped in the
datapath and never reaches a counter, so the row could only ever report zeros.

### Direct traffic

`GET /api/v1/runtime/direct-stats` reports `enabled`, `attached`,
`counter_since`, `up_bytes`, `up_packets`, `down_bytes`, `down_packets` and
`last_error`. Counter values are decimal strings. `enabled` is the effective
`api.direct_stats` switch (configuration plus the kernel/TC capability gate);
`attached` says whether at least one observer hook actually reached the
datapath. `last_error` keeps the most recent load/attach or partial-read
failure, so `enabled: true` plus zeros is distinguishable from a healthy
zero-traffic deployment. `counter_since` is the process-level start of the
counters and survives a reload.

The opt-in observer in `control/kern/direct_stats.c` runs beside tproxy on the
WAN/LAN interfaces dae binds, reads `conn_state_map` without writing it, and
counts flows already flagged as direct pass-through. A bridge is observed on its
member ports; the link watcher adds and removes those hooks when members join or
leave. The hook uses TCX when available and falls back to classic TC filters on
kernels without TCX; the fallback is logged because its ordering depends on the
interface's existing filters and on the clsact qdisc being installable.

The direction split is:

- upload: LAN ingress for forwarded client packets, and WAN egress for locally
  generated direct packets (`ingress_ifindex == 0`);
- download: LAN egress for forwarded replies, after DNAT, and WAN ingress only
  for replies delivered to a local socket. The LAN egress hook is what makes a
  masquerading gateway countable: the reply leaving the LAN interface carries
  the client's address, so its reversed tuple matches the upload state. A
  dual-role interface keeps the single combined WAN-ingress accounting and
  therefore still omits NAT-rewritten forwarded replies.

The figure is aggregate link bytes and a lower bound; there is no per-host,
per-interface or per-outbound split. The observer runs before tproxy, so
the first packet of each flow (and flows that predate a restart) is missed;
non-TCP/UDP traffic is skipped; non-initial fragments are skipped; a flow whose
`conn_state_map` entry is missing (map full or stateless pass-through) cannot be
counted; a local reply whose socket is wildcard-bound is not attributed to the
host; and single VLAN tags still present on an egress frame are skipped by the
parser, while stacked VLAN flows are counted only when tproxy established state
on an interface where the inner tag is exposed. With `api.direct_stats` off the
hooks are absent and every counter is zero.

`up_packets` and `down_packets` are **skb counts**, not on-wire packet counts.
GSO/TSO/GRO can make one skb represent several wire packets, so packet rate and
average packet size derived from these fields are biased; use them with that
caveat. The counters are not summed into `runtime.traffic`, whose total stays
userspace-only. They are folded into the builtin `direct` row of
`GET /api/v1/runtime/outbounds`, so a panel that only reads the existing
resources shows direct traffic without knowing this endpoint. The row then mixes
units: kernel-direct link bytes plus the `must_direct` payload bytes the relay
counted.

#### Overhead

Direct traffic never reaches userspace, so a high direct throughput does not add
userspace CPU or heap. The cost is bounded and lives in the kernel:

- Memory is fixed and independent of traffic. `direct_stats_map` is a per-CPU
  array of two `{bytes, packets}` records. `conn_state_map` is tproxy's own map,
  reused via a map replacement, and is not allocated again.
- CPU scales with packet rate, not byte rate. The ingress program is chosen by
  interface role: a LAN-only hook looks up only the upload tuple, a WAN-only
  hook only the reply tuple, and an interface bound with both roles runs the
  combined program. A direct packet performs one counter-map lookup. A WAN
  ingress direct reply also performs a local-socket lookup to separate local
  delivery from forwarded traffic; forwarded replies are accounted on LAN
  egress instead. A flow tproxy has marked as proxied stops at the conn-state
  entry, so proxied traffic pays the lookups but no counter update. Expect the
  cost to become visible only at very high packet rates with small packets;
  large-packet bulk transfers are dominated by the NIC and the stack.
- Failure is isolated: a load or attach failure is logged, recorded in
  `last_error`, and skipped; it cannot fail the bind or the daemon startup. The
  API returns the counters of the generations that could be read and reports a
  partial `last_error` instead of zeroing every counter.
- With `api.direct_stats` off the object is never loaded and nothing is attached.

The table below predates the removal of the NAT reverse index and the current
LAN-egress accounting. It is a reference for the earlier revision, not a
measurement of the current code. The current observer's memlock has not been
measured. To measure on another system, set
`sysctl kernel.bpf_stats_enabled=1` and read `run_cnt` and `run_time_ns` for the
`dae_direct_stats_*` programs from `bpftool prog show`; `bpftool map show`
reports the map memory.

| Traffic | Observer off | Observer on | Increase |
|---|---:|---:|---:|
| Plain TCP download | 903 | 1067 | 18% |
| Plain TCP upload | 1374 | 1829 | 33% |
| Plain UDP, 64 B, 256 flows | 326 | 572 | 75% |
| NAT TCP download | 832 | 1029 | 24% |
| NAT TCP upload | 1481 | 1912 | 29% |
| NAT UDP, 64 B, 256 flows | 352 | 590 | 68% |

### Memory

`GET /api/v1/runtime/memory` reports `process.rss_bytes`, the cgroup v2 reading
and the kernel memory charged to dae's eBPF objects, and
`GET /api/v1/runtime/memory/history` returns the retained series.

The cgroup section depends on the system. A cgroup v2 hierarchy exposes
`memory.current`, `memory.max` and `memory.events` to a child only after the
parent delegates the controller (`echo +memory > cgroup.subtree_control`). When
it is not delegated, `cgroup` is `null` and `capabilities.resources.runtime_memory`
does not advertise the cgroup metrics: the engine reports what it can read and
never fabricates a value. Memory is charged per allocation, so delegate the
controller before starting dae; pages allocated earlier are not charged
retroactively.

`memory.max` reading the literal `max` means unlimited, which is different from
"this system does not report cgroup memory": the limit metric stays advertised
and `cgroup.limit_bytes` is `null`, so a client can render "no limit" instead of
"unknown".

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
