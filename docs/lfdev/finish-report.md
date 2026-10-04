# LFIQ-Git/ocp fork: finish report

Fork-only file. It lives under `docs/lfdev/`, which upstream does not have, so it cannot conflict with an upstream merge.

Scope for the 2026-10-02 fleet run: lfdev-audit (security mode) and lfdev-harden only. This fork runs behind a Cloudflare Tunnel and Cloudflare Access.

## Fork position, 2026-10-03

- Fork point with `dtzp555-max/ocp`: `f62856b` (2026-09-27).
- Fork-only commits on `main`: 10, all security (ADR 0023, 0024, 0025, ADR 0017 Amendment 1, the `CLAUDE_AUTH_MODE` boot gate, relayed-client logging) plus the gitleaks and log-path fixes.
- Upstream since the fork point: 2 commits (`v3.42.0`, Claude Sonnet 5.5). No security content. Merged in this pass with a merge commit, so the fork is 0 behind and keeps upstream ancestry.
- Every fork branch (`fix/*`, `feat/trust-loopback-switch`) was merged through PRs #5 to #10; their content is on `main`.

## Audit (lfdev-audit, security mode)

Stack: Node 22+, ES modules, zero npm dependencies (`node:http`, `node:sqlite`, `node:crypto`). Tests: `test-features.mjs`, 1465 passing.

| Area | Result |
|---|---|
| Auth on every route | Pass. `/health` and `/dashboard` are public by design; every other route goes through the 3-mode auth block. All admin routes (`/usage`, `/status`, `/logs`, `/settings`, `/api/keys*`, `/cache*`) check `isAdmin`, which reads which credential matched, never a key name (ADR 0023, 0024). |
| Tunnel and loopback trust | Pass. A request carrying `cf-connecting-ip` or `x-forwarded-for` is remote (ADR 0023). `OCP_TRUST_LOOPBACK=0` closes the header-less loopback paths (ADR 0025). An unknown `CLAUDE_AUTH_MODE` refuses to boot. |
| Key handling | Admin, shared and anonymous keys are compared with `timingSafeEqual`. Per-app keys are stored in plaintext in the SQLite keys DB and matched by SQL equality. See decisions. |
| Request logging | Pass. Logs record sizes, counts, model, key name and hashes, not prompt text or full keys. Observe mode's `auth_would_reject` logs the first 8 characters of a rejected token (`keyPreview`). |
| Rate limits | Concurrency cap with a bounded queue and HTTP 429 (`CLAUDE_MAX_CONCURRENT`, `CLAUDE_MAX_QUEUE`); per-key daily, weekly and monthly quotas exist but are opt-in per key. No per-client-IP limit. |
| CSRF and DNS rebinding | Pass. Origin gate (ADR 0019) and declared hosts (ADR 0020). |
| Dependency advisories | None possible: no npm dependencies. Runtime exposure is the Node version on the host. |
| Secrets | `gitleaks git` over 429 commits and `gitleaks dir` over the tree: no leaks. CI runs gitleaks on every push. |

### Configuration-dependent exposure (not a code defect)

In `CLAUDE_AUTH_MODE=none`, or `shared` without `PROXY_API_KEY`, a relayed request is admitted without a credential and the spawned `claude` keeps its default tools (Bash, Write, Edit). Anyone who gets past the edge could run commands on the host. ADR 0023 Decision 5 keeps this deliberately so an operator can front an open OCP with an authenticating proxy. `multi` mode admits a keyless remote caller as `anonymous`, with tools removed. A tunneled deployment must run `shared` with `PROXY_API_KEY` set.

## Hardening (lfdev-harden)

No code change to `server.mjs` in this pass. The open items need a new ADR or a production action, so they are listed as decisions rather than guessed.

### Fixed

- Pulled upstream v3.42.0 (merge commit). `npm test`: 1465 passed, 0 failed. `scripts/b2-key-snapshot.mjs`: key sets match.

### Decisions needed

- **Refuse keyless relayed requests in every mode.** This would turn the configuration-dependent exposure above into a 401, at the cost of contradicting ADR 0023 Decision 5. It needs its own ADR. Recommendation: do it, opt-out by env var.
- **Hash per-app keys at rest** (SHA-256 of the key, compared by hash), with a migration for existing rows. Contract-neutral, but `keyPreview` in `GET /api/keys` reads the stored key and would need a stored prefix.
- **Per-client rate limit at the edge.** A Cloudflare rate-limiting rule on the hostname is cheaper than adding one to OCP. Set per-key quotas for the Vercel consumers.
- **`POST /api/keys` with an array `name` hangs** (admin-only). Open follow-up from ADR 0017 Amendment 1.
