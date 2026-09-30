// OCP network helpers — shared so server.mjs and tests use one definition. (issue #125)

// A bind address is "loopback" only if it cannot be reached from another host.
// Any other address (0.0.0.0, ::, a concrete LAN/Tailscale IP, etc.) is
// network-exposed and must trigger the TUI LAN gate.
export function isLoopbackBind(addr) {
  return addr === "127.0.0.1" || addr === "::1" || addr === "localhost" ||
         addr === "::ffff:127.0.0.1" || /^127\./.test(addr);
}

// ADR 0023. The request headers that mark a request as RELAYED by a reverse proxy or tunnel.
// A relayed request came from somewhere else, so it is not a localhost request even when the
// socket peer is loopback (cloudflared, a local nginx/Caddy, ngrok all connect from 127.0.0.1).
//
// Presence is what counts, never the value: an empty header still means something put it there.
// The check can only DOWNGRADE a request (loopback -> remote), so a local process that sends one
// of these headers gains nothing; it only gives up the localhost trust it already had.
//
//   cf-connecting-ip  set by Cloudflare on every request it relays, including cloudflared tunnels.
//   x-forwarded-for   the de facto relay header, added by most reverse proxies and tunnels.
//
// Not listed, and therefore NOT detected: `Forwarded` (RFC 7239) alone, `X-Real-IP` alone, or a
// proxy configured to send none of these. See ADR 0023 § "What this does not do".
export const RELAY_HEADERS = Object.freeze(["cf-connecting-ip", "x-forwarded-for"]);

// Returns the first relay header present on `headers` (Node's lower-cased IncomingMessage
// headers object), or null when none is.
export function relayHeaderOf(headers) {
  if (!headers) return null;
  for (const name of RELAY_HEADERS) {
    if (headers[name] !== undefined) return name;
  }
  return null;
}
