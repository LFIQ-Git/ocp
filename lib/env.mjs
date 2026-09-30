// OCP env-var parsing helpers.
//
// Fail-closed positive-integer parsing for numeric caps (body size, image
// byte/count limits). A misconfigured cap must NEVER silently disable a guard:
// `parseInt("unlimited", 10)` is NaN and `x > NaN` is always false, so a naive
// parse of CLAUDE_MAX_BODY_SIZE=unlimited would remove the body-size limit
// entirely (unbounded body → OOM). Likewise CLAUDE_MAX_BODY_SIZE=5MB naively
// parses to 5 (bytes) and bricks the proxy. So a present-but-invalid value is
// REJECTED (default kept, caller warns), not accepted. (PR #154 review F3.)
//
// Pure (no env access, no IO) so it is unit-testable without a live server.

// Parse `raw` as a strictly-positive base-10 integer of bytes/count (no unit
// suffix). Returns { value, ok, reason }:
//   - missing/empty        → { value: def, ok: true }               (use default)
//   - valid positive int   → { value: n,  ok: true }
//   - anything else        → { value: def, ok: false, reason }      (fail closed)
// Rejects: NaN ("unlimited"), non-positive ("0", "-1"), unit-suffixed ("5MB"),
// and fractional/ambiguous ("20.5", "0x10") values — String(n) !== trimmed catches
// any input parseInt only partially consumed.
export function parsePositiveInt(raw, def) {
  if (raw === undefined || raw === null || raw === "") return { value: def, ok: true };
  const trimmed = String(raw).trim();
  const n = parseInt(trimmed, 10);
  if (!Number.isFinite(n) || n <= 0 || String(n) !== trimmed) {
    return { value: def, ok: false, reason: "not a strictly-positive integer (bytes/count, no unit suffix)" };
  }
  return { value: n, ok: true };
}

// CLAUDE_AUTH_MODE. The only values server.mjs's auth block branches on. Matched EXACTLY: lowercase,
// no surrounding whitespace. Nothing is normalised, because every consumer compares the raw string
// (server.mjs's `AUTH_MODE === "shared"` and `"multi"` tests, `/health`'s `authMode`, `ocp`'s
// display) and a value that one of them folds and another does not is the same defect one level
// down. Unset or empty keeps the existing derivation (`shared` when PROXY_API_KEY is set, else
// `none`), so the caller decides that part.
export const AUTH_MODES = Object.freeze(["none", "shared", "multi"]);

// Returns null when `raw` is acceptable (unset, empty, or one of AUTH_MODES), else the boot error
// text. Before this, an unrecognised value fell through every `AUTH_MODE === …` test to the `none`
// branch: `CLAUDE_AUTH_MODE=sharde` (or `Shared`) booted with no auth at all while the operator
// believed shared-key auth was on. Pure, so the rule is unit-testable without booting a server.
export function authModeBootError(raw) {
  if (raw === undefined || raw === null || raw === "") return null;
  if (AUTH_MODES.includes(raw)) return null;
  const shown = JSON.stringify(String(raw).slice(0, 64));
  return `CLAUDE_AUTH_MODE=${shown} is not a recognised auth mode. Allowed values: ${AUTH_MODES.join(", ")} ` +
    `(exact, lowercase). Leave it unset to derive shared when PROXY_API_KEY is set, else none. Refusing to start ` +
    `rather than falling back to no auth.`;
}
