# ADR 0024 — In multi mode, admin comes from `OCP_ADMIN_KEY`, never from a key's name

- **Status**: Proposed (independent review pending)
- **Date**: 2026-09-30
- **Amends**: the `isAdmin` rule under the `none | shared | multi` auth block in `server.mjs` (grep `// 3-mode auth`), multi-mode arm only
- **Related**: ADR 0023 (the same fix for `shared` and `none` mode, and the follow-up this closes), ADR 0017 Amendment 1 (reserves the name `admin` for new keys), ADR 0006 (Class A/B taxonomy; this is route **(b)**, a semantics change)
- **Class**: Hybrid, for the same reason as ADR 0023: the auth block runs before routing, so it sits above Class B.1 and Class B.2 alike and gates the Hybrid `/usage`. ADR 0006 route (b): a request that used to execute now receives `403`.

## Context

In `CLAUDE_AUTH_MODE=multi` the admin rule was:

```js
const isAdmin = AUTH_MODE === "multi"
  ? authKeyName === "admin" || isLocalhost
  : …;
```

`authKeyName` is `"admin"` in two cases. One is intended: the bearer token matched `OCP_ADMIN_KEY`.
The other is not: a keys-DB key whose **name** is `admin`. `validateKey()` returns the row's name and
the multi branch assigns it to `authKeyName`, so the formula cannot tell the two apart. The keys API
accepts any name matching `^[A-Za-z0-9 ._-]{1,64}$`, which includes `admin`.

So in multi mode, whoever holds a DB key named `admin` is admin: `/api/keys` (mint and revoke keys),
`/settings` (change the proxy's runtime settings), `/logs`, and `/api/usage?all=true`. Multi mode is
the mode where per-user keys are handed to other people, so the holder of that key need not be the
operator.

ADR 0023 fixed the same shape in `shared` and `none` mode by deciding admin from which credential
matched, through an explicit flag (`remoteCredentialIsAdmin`), and left multi mode's formula as it
was on purpose. Its § "What this does not do" records this defect and its follow-ups list names it.

### Measured on the pre-change `server.mjs` (`d1fa70e`)

Live-server tests in `test-features.mjs` § `ADR 0024`, run against the unchanged formula (mutation M1
below): a key named `admin`, presented through a tunnel or from a direct LAN peer, got `200` on
`/api/keys` and `/settings`. With `OCP_ADMIN_KEY` unset, the same key got `200` through the tunnel,
so it was a remote admin path on a host whose operator had configured none.

## Decision

In multi mode, `isAdmin` is true for:

- a **genuine localhost** request (loopback socket, no relay header), exactly as today; or
- a remote request whose bearer token matched **`OCP_ADMIN_KEY`**.

Nothing else. In particular, a keys-DB key is never admin in multi mode, whatever its name.

The implementation reuses ADR 0023's flag rather than adding a second one: the multi branch sets
`remoteCredentialIsAdmin = true` at the one place it compares the token to `OCP_ADMIN_KEY`, and the
multi arm of the formula becomes `remoteCredentialIsAdmin || isLocalhost`. After this change no arm of
`isAdmin` reads `authKeyName`.

What does **not** change:

- **Localhost.** Its semantics are left as they are. A loopback request with no relay header is admin
  in every mode, with or without a token. (Whether loopback should confer trust at all is a separate
  switch with its own ADR.)
- **Authentication.** A DB key named `admin` still authenticates in multi mode. It is admitted,
  attributed under its name, and quota-bound like any other DB key. Only admin is withdrawn.
- **`authKeyName`.** A request carrying `OCP_ADMIN_KEY` is still recorded as `admin`. The name is
  still used for attribution and for `/api/usage` scoping; it is no longer used for authorization.
- **`shared` and `none` mode.** Untouched; ADR 0023 already decides them from the flag.

## Class mapping

- **Class A.** Not implicated. `server.mjs` has no inbound `/v1/messages` handler (`grep -n
  '/v1/messages' server.mjs` hits comments and the one outbound rate-limit probe behind the
  `// ALIGNMENT:` marker, which is untouched). Who may reach `/usage` is decided by `isAdmin`, which is
  the Class B synthesis layer of that Hybrid endpoint. No claim about `cli.js` is made or needed.
- **Class B.1** (`/v1/chat/completions`, `/v1/models`). ADR 0006. Neither route reads `isAdmin`, and
  no field, parameter or response key changes. A DB key named `admin` is served exactly as before.
- **Class B.2** (the grandfathered administrative endpoints). **A semantics change**: a multi-mode
  request carrying a DB key named `admin` that used to execute as admin now receives `403` on
  `/api/keys`, `/api/keys/:id`, `/api/keys/:id/quota`, `/settings`, `/logs` and `/cache*`, and
  `/api/usage` ignores its `?all=true`. That needs its own authorization under `ALIGNMENT.md` and ADR 0006, which is
  this ADR. Not ADR 0012: nothing is added to any response. `docs/governance/b2-response-keys.json` is
  unchanged, because its probes run from real loopback, which stays admin.

## Consequences

- **An operator who used a DB key named `admin` as their multi-mode admin credential loses remote
  admin.** Nothing in the repo tells anyone to do that: `docs/lan-mode.md` sets up multi mode with
  `OCP_ADMIN_KEY`, and the `ocp` CLI sends `OCP_ADMIN_KEY` or `~/.ocp/admin-key`. The fix for such an
  operator is to set `OCP_ADMIN_KEY` and use it. Localhost admin is unaffected, so the host itself can
  always recover.
- **With `OCP_ADMIN_KEY` unset, multi mode has no remote admin path.** That was the configuration's
  documented meaning (`setup.mjs` logs `OCP_ADMIN_KEY: (unset — admin endpoints disabled)`); the named
  key was an undocumented exception to it.
- **A surviving DB key named `admin` now reads the `admin` usage bucket.** `/api/usage` scopes a
  non-admin caller to its own `key_name`, and requests made with `OCP_ADMIN_KEY` are recorded as
  `admin`, so such a key sees the admin key's usage rows (model, character counts, timings; no
  content). Before this change it saw everything, as admin, so this is strictly less exposure, but it
  is not none. ADR 0017 Amendment 1 stops new keys taking the name. An operator with such a key should
  revoke it: `ocp keys revoke admin`.
- **No new configuration.** No flag, no env var, no transition switch. The change removes a path that
  was never documented, and localhost remains the recovery route.

### What this does not do

- It does not rename, revoke or otherwise touch existing keys named `admin`.
- It does not change how genuine localhost is classified, or what it is trusted with.
- It does not change `shared` or `none` mode.

## Evidence

Live-server tests in `test-features.mjs`, section `ADR 0024 (multi mode: admin by credential, not by
name)`, using `ltBootFresh` with the fake `claude`. The key named `admin` is written straight into the
server's key store rather than minted, which is how one exists on a host that created it before ADR
0017 Amendment 1, and keeps the tests independent of that change's merge order.

| Test | Claim |
|---|---|
| `multi mode, through the tunnel — a DB key NAMED "admin" gets 403 …, OCP_ADMIN_KEY gets 200` | premise: the named key authenticates (`200` on chat, where an unknown key is `401`); named key `403` on `/api/keys` and `/settings`; `OCP_ADMIN_KEY` `200` on both; loopback `200` |
| `multi mode, direct LAN peer — …` | same pair from a non-loopback, unrelayed peer (premise: keyless caller `403`); skips on a host with no non-internal IPv4 interface |
| `multi mode with NO OCP_ADMIN_KEY — …` | named key through the tunnel `403`; the same key from loopback `200` |

Mutations, each applied to a file backup and restored byte-identical:

| Mutation | Result |
|---|---|
| M1: restore `authKeyName === "admin" \|\| isLocalhost` as the multi arm | all 3 red, each on its named-key assertion |
| M2: drop `remoteCredentialIsAdmin = true` from the multi branch | the two tests that use `OCP_ADMIN_KEY` remotely go red where they use it (the tunnel test on its admin-key control, the LAN test on its admin-key seeding premise); the no-admin-key test stays green, as it should |
