# ADR 0025 — `OCP_TRUST_LOOPBACK=0`: an operator switch that turns loopback trust off

- **Status**: Proposed (independent review pending)
- **Date**: 2026-09-30
- **Amends**: the `isLocalhost` classification at the top of the `none | shared | multi` auth block in `server.mjs` (grep `// 3-mode auth`)
- **Related**: ADR 0023 (relayed requests are remote; this closes its "Residual fail-open"), ADR 0019 (the other threat model a local process falls under), ADR 0006 (Class A/B taxonomy; this is route **(b)**, a semantics change, opt-in)
- **Class**: Hybrid, for the same reason as ADR 0023: the auth block runs before routing, so it sits above Class B.1 and Class B.2 alike and gates the Hybrid `/usage`. ADR 0006 route (b): with the switch set, a request that used to execute receives `401` or `403`.

## Context

After ADR 0023 a request is `localhost`, and therefore never refused and always admin, when its
socket peer is loopback **and** it carries no relay header (`cf-connecting-ip`, `x-forwarded-for`).
ADR 0023 § "What this does not do" names the paths that still reach the port that way, and so still
get full trust:

- a `cloudflared` **`tcp://`** ingress, which forwards bytes and adds no HTTP header;
- Cloudflare WARP private-network routing to the host;
- an SSH `-L` port forward;
- any reverse proxy configured to strip or not add the relay headers.

On such a host OCP's own auth is inert for exactly those callers, whatever `CLAUDE_AUTH_MODE` and
`PROXY_API_KEY` say. Nothing inside a request separates "a process on this host" from "a remote
client whose bytes a local forwarder is carrying", so there is no rule OCP can apply per request. The
operator knows which of the two their host has; OCP cannot. ADR 0023 therefore recorded the cure as
an explicit operator switch with its own ADR. This is that ADR.

## Decision

### 1. The switch

`OCP_TRUST_LOOPBACK`. **Default on**: unset, the classification is exactly ADR 0023's, byte for byte,
so upstream behaviour does not move. **`OCP_TRUST_LOOPBACK=0` turns loopback trust off**:

```js
const isLocalhost = TRUST_LOOPBACK && isLoopbackPeer && !relayedBy;
```

With it off, a loopback socket confers no trust at all. A loopback request takes the remote path of
the auth block exactly as a direct LAN caller does, under the configured mode's rules:

| Mode | Loopback caller with trust off |
|---|---|
| `shared`, `PROXY_API_KEY` set | `OCP_ADMIN_KEY` → admin; `PROXY_API_KEY` → admin (`shared`); a keys-DB key → admitted, not admin; anything else → the existing `401`. `OCP_REMOTE_AUTH_OBSERVE=1` applies: a missing or unknown key is admitted as `unverified`, not admin, and logged as `auth_would_reject`. |
| `multi` | `OCP_ADMIN_KEY` → admin; `PROXY_ANONYMOUS_KEY` or no token → `anonymous`, not admin; a keys-DB key → admitted, not admin; an unknown key → the existing `401`. |
| `none`, or `shared` without `PROXY_API_KEY` | Admitted and admin, because those configurations admit an unrelayed remote caller without a credential (ADR 0023 Decision 4). The switch changes nothing observable here, and the boot log says so. |

Nothing else in the auth block changes. The admin rules, the observe mode and the 401 bodies are
ADR 0023's (and, for multi mode's admin rule, whichever of ADR 0023 or ADR 0024 is in force).

`/health` stays public. It also stops showing `anonymousKey` to a loopback caller, because that is
gated on `isLocalhost`; `PROXY_ADVERTISE_ANON_KEY=1` still advertises it.

### 2. Parsing

`!== "0"`, which is the repo's convention for a default-on switch (`OCP_TOOL_CALLING`,
`OCP_MULTIBLOCK_INPUT`). A value that is neither `0` nor `1` keeps trust **on**, which is the
fail-open direction, so it gets a boot `WARNING` saying trust stays on. That mirrors what ADR 0023
did for `OCP_REMOTE_AUTH_OBSERVE`.

### 3. Boot log

- Trust off: a line on stderr naming the switch, saying loopback callers authenticate like remote
  ones, and saying local tools must send `OCP_ADMIN_KEY`.
- Trust off in `none` mode, or `shared` mode without `PROXY_API_KEY`: a `WARNING` that it changes
  nothing there, and why.
- Always, in the startup banner next to `Auth mode:` and `Bind:`: `Loopback trust: on (…)` or
  `Loopback trust: OFF (OCP_TRUST_LOOPBACK=0; …)`.

### 4. Local tooling

With trust off, anything on the host that calls a non-public route must authenticate. Checked for
every caller in the repo:

| Caller | Before this change | After |
|---|---|---|
| `ocp keys …`, `ocp usage` (per-key section) | sent `OCP_ADMIN_KEY` or `~/.ocp/admin-key` via `_curl` | unchanged |
| `ocp usage` (`/usage`), `ocp status`, `ocp logs`, `ocp models`, `ocp settings` (GET and PATCH) | sent **no** credential (bare `curl`) | now go through `_curl`, so they send the same key when one is available. With trust on this changes nothing: a loopback caller is admin with or without it. |
| `ocp health`, `ocp doctor`, `setup.mjs`, and the `/health` probes in `ocp update` and `ocp restart` | `/health`, public | unchanged, no key needed |
| `ocp update`'s final `/v1/models` check (`scripts/upgrade.mjs`, grep `/v1/models > /dev/null`) | sends no credential | **unchanged — gap.** With trust off in `shared` or `multi` mode that request gets `401`, `curl -sf` fails, and `ocp update` reports an error after the upgrade itself has landed. Left alone because `upgrade.mjs` is the most heavily governed script in the repo and that line is not reachable from the suite (`!opts.mockProbe`); an operator using the switch should verify with `ocp doctor` after `ocp update`. |
| `ocp-plugin/index.js` (OpenClaw plugin: `/usage`, `/status`, `/settings`, `/logs`, `/v1/models`, `/v1/chat/completions`) | sends no credential | **unchanged — gap.** Its base URL is configurable and may be remote, so sending the admin key from it is a separate decision. With trust off, only its `/health` calls work. |

The `ocp` CLI still does not send `PROXY_API_KEY`. In `shared` mode with trust off, an operator who
has set only `PROXY_API_KEY` must also set `OCP_ADMIN_KEY` (in the shell, or in `~/.ocp/admin-key`)
for `ocp` to reach the admin API. The boot line says so.

## Class mapping

- **Class A.** Not implicated. `server.mjs` has no inbound `/v1/messages` handler (`grep -n
  '/v1/messages' server.mjs` hits comments and the one outbound rate-limit probe behind the
  `// ALIGNMENT:` marker, which is untouched). No claim about `cli.js` is made or needed.
- **Class B.1** (`/v1/chat/completions`, `/v1/models`). ADR 0006. OpenAI's specification defines
  bearer authentication and does not define which callers a self-hosted server trusts without one.
  No field, parameter or response key changes; a refusal reuses the mode's existing `401` body.
- **Class B.2**. **A semantics change, opt-in.** With `OCP_TRUST_LOOPBACK=0`, a loopback request that
  used to execute as admin now receives `401` (no or bad key) or `403` (a non-admin credential). That
  is a new authorization under `ALIGNMENT.md` and ADR 0006, which is this ADR. With the switch unset
  every endpoint behaves exactly as before. Not ADR 0012: nothing is added to any response.
  `docs/governance/b2-response-keys.json` is unchanged: its fixture does not set the switch, and its
  probes run from real loopback.

## Consequences

- **Default installs see no change** except one banner line, `Loopback trust: on (…)`.
- **An operator can close ADR 0023's residual fail-open** on a host where a forwarder delivers remote
  traffic from loopback without a relay header. In `shared` or `multi` mode, with the switch off, OCP's
  own auth applies to every request, whichever path it arrived by.
- **Local tooling needs the admin key.** The `ocp` CLI sends it when it has one; the two gaps above
  are documented, not fixed.
- **A process on the host is not made safe.** It can still read `~/.ocp/admin-key`, the service
  environment, or the operator's credentials directly. ADR 0019 records that threat model as out of
  scope, and this switch does not change it. What it removes is the network path that impersonates a
  local process.
- **`none` mode gains nothing.** Its meaning is "no auth", and ADR 0023 Decision 5 keeps it that way.
  Remote admin through `none` mode is still impossible through a relay, and a loopback caller is
  still admin, switch or not.

## Evidence

Tests in `test-features.mjs`, section `ADR 0025 (OCP_TRUST_LOOPBACK=0)`, using `ltBootFresh` and
the fake `claude`. Every live test sends requests from real loopback with no relay header.

| Test | Claim |
|---|---|
| `OCP_TRUST_LOOPBACK=0, shared mode — a loopback request with no token is 401; the admin key is 200 on an admin route` | boot warning and banner; no token `401` on `/api/keys` and on chat with the existing body; bogus key `401`; `OCP_ADMIN_KEY` `200` on `/api/keys` and `/settings`; `PROXY_API_KEY` admin; a DB key admitted on chat and `403` on the admin API; `/health` `200` |
| `ADR 0025 control: OCP_TRUST_LOOPBACK unset — …` | the same loopback requests: no token `200` on `/api/keys`, bogus key `200` on chat; banner says on; no warning |
| `OCP_TRUST_LOOPBACK=0, multi mode — …` | no token `403` on `/api/keys`; bogus key `401`; admin key `200` |
| `OCP_TRUST_LOOPBACK=0 with OCP_REMOTE_AUTH_OBSERVE=1 — …` | bogus loopback key `200` as `unverified`; `auth_would_reject` with `relayedBy: null`; `403` on the admin API |
| `OCP_TRUST_LOOPBACK set to anything but 0 keeps trust ON and warns; =0 in none mode warns …` | `"false"` warns and loopback stays admin; `0` in `none` mode warns and loopback stays admin |
| `the ocp CLI sends the admin key on every local admin call …` | `ocp usage`, `status`, `logs`, `models`, `settings`, `settings timeout 60000` each pass `Authorization: Bearer <key>` to curl when a key is available, and none when it is not |

Mutations, each applied to a file backup and restored byte-identical:

| Mutation | Result |
|---|---|
| M1: `isLocalhost` ignores `TRUST_LOOPBACK` | shared, multi and observe tests red on their first loopback claim; the control and the parsing test green |
| M2: default flipped (`=== "1"`) | the control red on `a loopback request with no token is admin … got 401`; the parsing test red on its warning |
| M3: `ocp settings` GET back to bare `curl` | the CLI test red on `` `ocp settings` must send the admin key `` |
