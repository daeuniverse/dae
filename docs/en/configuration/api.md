# Native API

dae can expose a native HTTP control-plane API compatible with the
[api-standardize](https://github.com/daeuniverse/api-standardize) contract. The
listener is **disabled by default**.

This page covers everything needed to configure and deploy the listener.
Endpoint behaviour and the resource contract live in
[development/api.md](../development/api.md).

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
