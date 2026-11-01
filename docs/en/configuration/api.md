# Native API

dae can expose a native HTTP control-plane API compatible with the
[api-standardize](https://github.com/daeuniverse/api-standardize) contract. The
listener is **disabled by default**.

This page covers configuring and deploying the listener, plus the directory
layout that API writes require. Endpoint behaviour and the resource contract live
in [development/api.md](../development/api.md).

## Configuration

```dae
api {
    enabled: true
    listen: '127.0.0.1:9527'
    secret: 'replace-with-a-long-random-token'
    allow_anonymous_loopback: false
    allow_origins: 'http://localhost:3000'
    allowed_hosts: 'panel.example,panel.example:443'
    config_write: false
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
| `config_write` | `false` | Allow API callers to replace configuration sources. Requires a non-empty `secret` and the directory layout below. |

## Editing configuration through the API

`config_write: true` is only a switch; whether writes are possible also depends on
how the configuration **directory is structured**. dae never edits lines in
place, it replaces a whole source file, so the configuration has to be split the
standard way:

```sh
# tree /etc/dae
/etc/dae
├── config.dae          # entry: one include block only
├── api.dae             # api block; hidden from the API, edit by hand only
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

Every condition below must hold. One failure disables writes entirely, so there
is never a state where one file was replaced and another was not:

| # | Condition |
|---|---|
| 1 | The entry file must be named `config.dae`. |
| 2 | The entry may hold exactly one `include` block and no other section. |
| 3 | The expanded include set must be exactly `config.d/*.dae` and `api.dae`. |
| 4 | `api.dae` must exist, and `config.d/` must hold the six module files above. |
| 5 | A module under `config.d/*.dae` must not `include` anything else. |
| 6 | Each section may come from exactly one file, so `dns` belongs to `dns.dae`. |
| 7 | No file may be group-writable or group-executable, nor accessible to other users; `0640` or `0600` is expected. |
| 8 | `config.d/` must be writable, because a replacement writes `.bak` and a temp file. |

With the layout in place, each edit replaces its module file: nodes replace
`node.dae`, groups `group.dae`, routing `routing.dae`, DNS `dns.dae`,
subscriptions `subscription.dae`, and so on. A configuration that is not split
this way cannot be edited through the API.

When a condition fails, writes answer `403 permission_denied` with the reason in
`details.reason`, also visible as `resources.config.x-dae.layout.reason` in
`GET /api/v1/capabilities` (`writes_disabled` or `layout_unmanaged`), while
`layout.kind` stays `managed` or `unmanaged`.

Further constraints:

- `api.dae` is hidden from the API: it is absent from the source list and its ID
  answers `404`. Changing the listen address, the port or the secret therefore
  stays a manual edit plus a restart.
- `config.dae` itself is read-only (`entry_source`) and a replacement may not
  change the `api` block.
- A replacement is validated with the same chain as `dae validate -c`; a rejected
  candidate answers `422` with line numbers and nothing is written.

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

## Reload behavior

All `api` fields are restart-required. A reload that changes them is rejected or
keeps the previous listener and logs a warning; the listener is never partially
recreated.

## Example

```bash
curl http://127.0.0.1:9527/api
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9527/api/v1/runtime
```
