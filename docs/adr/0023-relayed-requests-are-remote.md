# ADR 0023 — A request relayed by a tunnel or reverse proxy is remote, even on a loopback socket

- **Status**: Proposed (independent review pending)
- **Date**: 2026-09-30
- **Amends**: the `none | shared | multi` auth block in `server.mjs` (grep `// 3-mode auth`) and the `isAdmin` rule beneath it
- **Related**: ADR 0006 (Class A/B taxonomy; this is route **(b)**, a semantics change), ADR 0019 and ADR 0020 (the other cross-cutting gate at the top of `handleRequest`)
- **Class**: Hybrid. The auth block runs before routing, so it sits above Class B.1 (`/v1/chat/completions`) and Class B.2 (`/api/keys`, `/settings`, `/logs`, `/api/usage`, `/cache*`) alike, and gates access to the Hybrid `/usage`. ADR 0006 route (b): a request that used to execute now receives `401` or `403`.

## Context

The auth block decided "is this localhost?" from the socket peer alone:

```js
const isLocalhost = remoteAddr === "127.0.0.1" || remoteAddr === "::1" || remoteAddr === "::ffff:127.0.0.1";
```

and a localhost request is never refused (the branch's own comment: *"Localhost always allowed — try
to identify key if provided, but never reject"*). In `none` and `shared` modes every request was
also admin, because `isAdmin = AUTH_MODE !== "multi" || …`.

That rule is correct only when nothing sits between the client and the socket. A reverse proxy or
tunnel running on the same host connects to OCP from loopback, so every request it relays is
classified as localhost, whoever sent it.

### Measured in production, 2026-09-30

A fork deployment runs OCP on a Windows host behind a Cloudflare Tunnel. The `cloudflared` ingress is
`service: http://localhost:3456`. The environment is `CLAUDE_AUTH_MODE=shared`, `PROXY_API_KEY` set,
`OCP_ADMIN_KEY` set, `CLAUDE_ALLOWED_TOOLS=WebSearch,WebFetch`, `OCP_ALLOWED_HOSTS=ocp.lfiq.app`.
Cloudflare Access sits in front of the hostname.

| Observation | Consequence |
|---|---|
| A made-up bearer token, `ocp_bogus`, got **HTTP 200** on `/v1/chat/completions` through the public hostname. | `PROXY_API_KEY` enforced nothing for any request that came through the tunnel, which is every request that did not originate on the host. |
| `isAdmin` was true for those requests. | `/api/keys`, `/settings`, `/logs`, `/api/usage` and `/cache` were open to anyone who got past Cloudflare Access. |
| **All 720** usage rows recorded since May carry `key_name = "local"`. | Per-key attribution and per-key quotas never applied. The localhost branch names only the admin key, the anonymous key and DB keys, so the shared `PROXY_API_KEY` (and any unknown token) was recorded as `local`. |

The only control actually protecting the admin API and the spawned `claude` was Cloudflare Access.
OCP's own auth was inert. The live-server suite reproduces all three observations on the pre-fix
`server.mjs` (see Evidence).

## Decision

### 1. A relayed request is remote

A request is **relayed** when it carries a `cf-connecting-ip` or an `x-forwarded-for` header. A
relayed request is never localhost, whatever its socket peer. The check is presence, not value:
an empty header still means something put it there. The list lives in one place,
`lib/net.mjs` § `RELAY_HEADERS`, and `server.mjs` reads it through `relayHeaderOf()`.

**This cannot be used to escalate.** The check only ever moves a request from "localhost" to
"remote". A local process that sends one of these headers gives up the localhost trust it already
had and gains nothing. An internet client cannot use it either: the header can only make the
request look *less* trusted than the socket says. So the header does not need to be authenticated,
and no allowlist of trusted proxies is needed.

**Why `cf-connecting-ip`.** It is the header the production deployment carries: Cloudflare sets it
on every request it proxies, including requests delivered through `cloudflared`. (Stated from
Cloudflare's documentation and the operator's deployment, not re-measured by this change; the
tests send the header themselves.)

**Why `x-forwarded-for` as well.** It is the de facto relay header, added by most reverse proxies
and tunnels that are not Cloudflare. Caddy's `reverse_proxy` adds it by default; nginx adds it when
configured with the usual `proxy_set_header X-Forwarded-For`. (Reasoned from those products'
documented defaults, not measured here.) Every one of those deployments has the same defect as the
Cloudflare one when the proxy runs on the OCP host. The argument that made `cf-connecting-ip` safe
applies unchanged, because presence can only downgrade. The cost is that an operator who put a
local TLS proxy in front of OCP and relied on "localhost" trust through it now has to present a key.
That is the fix working, not a regression: the proxy cannot know who is on the other side.

### 2. Remote requests in `AUTH_MODE=shared`

A remote request (relayed, or from a non-loopback socket) is admitted with any of:

| Token | `authKeyName` | `authKeyId` | Admin |
|---|---|---|---|
| `OCP_ADMIN_KEY` | `admin` | — | **yes** |
| `PROXY_API_KEY` | `shared` | — | **yes**, exactly as before |
| a valid, non-revoked key in the keys DB (`validateKey()`) | the key's name | the key's id | **no** |

Anything else, including no token, is refused with the existing shared-mode `401` and body
(`Unauthorized: invalid or missing Bearer token`, `type: "auth_error"`), unless observe mode is on.

Per-app keys now carry `authKeyId`, so per-key quotas (`checkQuota`) and per-key attribution apply
to them. Before this change a remote shared-mode caller could only present the one shared key.

If `PROXY_API_KEY` is **unset** in shared mode, the existing behaviour is kept: the boot warning
already says all requests pass unauthenticated, and they still do, as `remote`. The admin key and DB
keys are still recognised if presented.

### 3. Observe mode: `OCP_REMOTE_AUTH_OBSERVE=1`

Default off, which means enforce. When `OCP_REMOTE_AUTH_OBSERVE=1` and the request would have been
refused under Decision 2 (shared mode, `PROXY_API_KEY` set, token missing or unknown), the request
is **admitted** as `authKeyName = "unverified"`, which is **not** admin, and one warn-level event is
logged through the existing `logEvent`:

```json
{"level":"warn","event":"auth_would_reject","reason":"unknown_key","keyPreview":"ocp_bogu",
 "relayedBy":"cf-connecting-ip","clientIp":"203.0.113.7","method":"POST","path":"/v1/chat/completions"}
```

`reason` is `missing_key` or `unknown_key`. `keyPreview` is the first 8 characters, never the token.
The purpose is operational: run one day in observe mode, read the `auth_would_reject` lines to find
consumers still sending a stale or no key, fix them, then unset the variable.

The name follows the repo's convention for OCP-owned boolean switches (`OCP_LOCAL_TOOLS`,
`OCP_SPAWN_REAL_HOME`, `OCP_TUI_STREAM`: the value `"1"`). Because a misspelled value would silently
leave enforcement on, any other non-empty value prints a boot warning saying observe mode is OFF.
When it is on, a boot warning says so, since it admits requests that would otherwise be refused.

### 4. `isAdmin`

- `multi` mode: unchanged formula, `authKeyName === "admin" || isLocalhost`. The only change is that
  `isLocalhost` is now false for relayed requests.
- `none` and `shared` modes: admin is
  - a localhost request (loopback socket, no relay header), or
  - a remote request that presented `OCP_ADMIN_KEY` or `PROXY_API_KEY`, or
  - an **unrelayed** remote request that was never asked for a key (`none` mode, or `shared` mode
    with no `PROXY_API_KEY`). This is upstream's behaviour for a direct LAN client, kept as is.
- Not admin: a per-app DB key, `unverified`, and any relayed request that did not present one of the
  two admin credentials.

Admin is decided from **which credential matched**, never from `authKeyName`. Two explicit flags
carry it: `remoteCredentialIsAdmin` (the token matched `OCP_ADMIN_KEY` or `PROXY_API_KEY`) and
`admittedWithoutCredential` (none mode, or shared mode with no `PROXY_API_KEY` and nothing matched).
The keys API accepts any name matching `^[A-Za-z0-9 ._-]{1,64}$`, so a DB key can carry an internal
bucket name. Tests mint keys named `remote`, `local`, `shared`, `admin`, `unverified` and
`anonymous`, use them from a direct LAN peer and through the tunnel, and prove each is refused on the
admin API.

> **Review correction (PR #5).** The first version of this decision tested the third arm as
> `!relayedBy && authKeyName === "remote"`. Independent review showed that a DB key **named**
> `remote` was then admin for a direct LAN caller in shared mode (`200` on `/api/keys` and
> `/settings`, against `403` for a key named `app1`). The relayed path was never affected. The arm
> now reads the `admittedWithoutCredential` flag, and mutation M17 reinstates the old test to prove
> the new LAN-peer tests catch it.

### 5. `AUTH_MODE=none` and relayed requests

`none` means no auth, and upstream documents it that way, so a relayed request is still **admitted**
and served. It is **not admin**. Real loopback callers are unchanged: admitted and admin.

Refusing relayed requests in `none` mode would turn a documented "open" mode into something else
and break any operator who deliberately fronts an open OCP with an authenticating proxy. Leaving
them admin would keep the exact defect this ADR exists to close, since "admin" in `none` mode is
what opens `/settings`, `/api/keys` and `/logs`. The consequence, stated plainly: in `none` mode
there is no path to the admin API through a relay. An operator who needs remote admin should run
`shared` mode, which is what the affected deployment already does.

### 6. Boot log

When observe mode is on, a `WARNING:` line is printed next to the existing `AUTH_MODE` warnings. If
the variable is set but cannot take effect (not `shared` mode, or no `PROXY_API_KEY`), the warning
says it has no effect.

## Class mapping

Same structure as ADR 0019 and ADR 0020: the change is in the shared request pipeline, so each class
is answered separately.

- **Class A.** `server.mjs` has **no inbound `/v1/messages` handler**: `grep -n '/v1/messages'
  server.mjs` hits only comments and the one outbound `fetch("https://api.anthropic.com/v1/messages")`
  of the rate-limit probe that `/usage` uses (introduced by the block marked `// ALIGNMENT:`). That outbound call is untouched: same URL, headers and body.
  Who may *reach* `/usage` is decided by `isAdmin`, which belongs to the Class B synthesis layer of
  that Hybrid endpoint, not to the wire call. No claim about `cli.js` behaviour is made or needed,
  and Rules 1 to 5 are not implicated.
- **Class B.1** (`/v1/chat/completions`, `/v1/models`). ADR 0006. OpenAI's specification defines
  request and response fields and bearer authentication; it does not define how a self-hosted
  compatible server decides which bearer tokens it accepts. No field, parameter or response key is
  added, removed or retyped. The refusal reuses the existing shared-mode `401` body.
- **Class B.2** (the grandfathered administrative endpoints). **A semantics change, not a
  behaviour-preserving refactor.** A relayed request that previously executed as admin now receives
  `401` (no or bad key) or `403` (per-app key, or `none` mode). Under `ALIGNMENT.md` and ADR 0006
  that needs its own authorization rather than the grandfather clause, which is what this ADR is.
  Deliberately **not** filed under ADR 0012: nothing is added to any response.
  `docs/governance/b2-response-keys.json` is unchanged, which is expected: its probes are real
  loopback requests with no relay header.

## Consequences

- **Enforcement starts on upgrade.** Every consumer reaching a shared-mode OCP through a tunnel or
  reverse proxy must present `PROXY_API_KEY`, `OCP_ADMIN_KEY` or a DB key. Operators with consumers
  of unknown key hygiene should upgrade with `OCP_REMOTE_AUTH_OBSERVE=1`, read the
  `auth_would_reject` lines, fix the consumers, then remove the variable.
- **Per-app keys work remotely in shared mode**, for relayed and direct LAN callers alike, and they
  are attributed and quota-bound, but they are not admin. Before, a direct LAN shared-mode caller
  presenting a DB key got `401`, since only the shared key was accepted. So no direct LAN caller
  loses admin: the shared key keeps it, and the admin key is now accepted too.
- **`/health` stops showing `anonymousKey` through a relay.** It was shown when `isLocalhost`, which
  every relayed request used to be. `PROXY_ADVERTISE_ANON_KEY=1` still advertises it everywhere.
- **`unverified` callers can read `unverified` usage rows.** `/api/usage` scopes a non-admin caller to
  its own `key_name`, and in observe mode every unverified caller shares one. The rows hold model,
  character counts, timings and success, no content. This lasts only as long as observe mode.
- **`none` mode has no remote admin path** (Decision 5).

### What this does not do

- It does not detect a proxy that sends **none** of the listed headers, or only `Forwarded`
  (RFC 7239) or only `X-Real-IP`. Such a proxy is still classified by its loopback socket. A unit
  test pins that those two headers are not on the list, so adding them is a visible, deliberate
  change to this ADR.
- It does not change how a genuinely local process is treated. Anything running on the host can
  already reach the spawned `claude` directly, as ADR 0019 records. Different threat model.
- It does not fix `multi` mode's use of the name `"admin"` for admin: a DB key named `admin`
  presented in multi mode is still admin there. That predates this ADR, and Decision 4 keeps multi
  mode's formula as it was. Recorded so it is not mistaken for covered.
- It does not replace Cloudflare Access. It makes OCP's own auth meaningful behind it.
- **Residual fail-open.** Any path that reaches the port from loopback **without** adding a relay
  header is still localhost and admin: a `cloudflared` `tcp://` ingress, WARP private-network
  routing, an SSH `-L` forward, or a proxy that strips the headers. Closing that needs an explicit
  operator switch that turns loopback trust off entirely. Follow-up, its own ADR.

### Follow-ups recorded, not done here

- **Reserve the internal bucket names at key creation** (`admin`, `local`, `remote`, `shared`,
  `unverified`, `anonymous`). After this ADR no name confers admin, but a DB key with one of those
  names still shares that bucket's rows on `/api/usage` and in usage attribution. Refusing them is a
  change to `POST /api/keys`'s accepted request shape, which ADR 0017 governs, so it needs its own
  ADR 0017 amendment and PR rather than being folded into a security fix.
- **Multi mode's admin-by-name**, above. Fixing it changes multi mode's admin rule, which this ADR
  deliberately leaves alone.
- `admin_usage_full_scope` logs the socket peer as `ip`, which is `127.0.0.1` for a relayed caller.
  Logging only, not a trust decision.

## Evidence

Live-server tests in `test-features.mjs`, section `ADR 0023 (relayed requests are remote)`, using
the existing `ltBootFresh` fixture with the fake `claude` and the `LT_SECRETS` inbound secrets. Each
sends the same request with and without the relay header, so each half is the other's control.

| Test | Claim |
|---|---|
| `relayHeaderOf reports cf-connecting-ip and x-forwarded-for by PRESENCE` | the detection rule, including that `Forwarded` / `X-Real-IP` are not on it |
| `shared mode — a bogus key is REFUSED through the tunnel and still admitted on real loopback` | the production repro, `401` with the existing body, and the loopback control |
| `shared mode — tunneled requests are attributed to the key that made them, never to "local"` | DB key attributed by name; shared key attributed `shared`; no `local` row |
| `shared mode — through the tunnel the admin API takes the admin or shared key, and refuses a per-app key` | `403` for a per-app key and for a DB key **named** `admin`; `200` for both admin credentials and for loopback |
| `shared mode, direct LAN peer — no per-app key NAME confers admin …` | server bound to the host's LAN address, so the peer is non-loopback and unrelayed (premise: keyless `401`); keys named `remote`, `local`, `shared`, `admin`, `unverified`, `anonymous` and `app1` all `403` on `/api/keys` and `/settings`; both admin credentials `200` |
| `shared mode with NO PROXY_API_KEY — a keyless direct LAN caller keeps upstream admin …` | keyless LAN caller `200` (upstream pass-through); key named `remote` `403`; relayed keyless caller `403` |
| `OCP_REMOTE_AUTH_OBSERVE=1 admits a bogus tunneled key as "unverified" …` | boot warning, `200`, `auth_would_reject` with an 8-character preview and not the token, `missing_key` for no token, `unverified` attribution, `403` on the admin API |
| `none mode — a tunneled request is still admitted, but is not admin` | Decision 5 |
| `none mode, direct LAN peer — upstream admin is kept for the unrelayed caller …` | LAN keyless `200`, same peer relayed `403` |
| `multi mode — a tunneled request is no longer localhost-admin` | Decision 4, multi mode |

The three LAN-peer tests skip, and say so, on a host with no non-internal IPv4 interface. Against the
**pre-fix** `server.mjs` (branch base) the first seven tests went `1 passed, 6 failed`: only the pure
`relayHeaderOf` unit test passed, because it does not touch the server. The mutation table and
full-suite result are in the PR body.
