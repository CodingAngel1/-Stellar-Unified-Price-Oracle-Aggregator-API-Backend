# Rate limit tiers and quota governance

The API applies per-key rate limits so quota enforcement is predictable and operationally visible to integrators.

## Tier behavior

- `free`: baseline quota for trial and low-volume traffic
- `pro`: higher request budget for production traffic
- `enterprise`: elevated allowance for partner and high-volume clients
- `admin`: operational access with explicit admin controls

Consumers receive quota usage through the standard rate limit headers:

- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset`
- `Retry-After` on 429 responses

These headers are emitted alongside the API key validation flow so abuse detection and usage monitoring remain actionable.

## Header trust model

Client-supplied headers never change a caller's own allowance. A header is
considered input only when it comes from a proxy the operator configured as
trusted, and is ignored otherwise (issue #594).

### `TRUSTED_PROXY_IPS`

Comma-separated IPs or IPv4 CIDRs (for example `10.0.0.0/8, 192.0.2.10`) that
identify the load balancer/CDN in front of the API. The setting is read from
the environment at request time.

- **Untrusted peer** (the default: no value configured): `X-Forwarded-For`,
  `x-geo-region`, `cf-ipcountry` and similar headers are stripped from
  consideration entirely. The limit is exactly the configured base value, so a
  client cannot raise its own ceiling by sending headers.
- **Trusted peer**: the first `X-Forwarded-For` hop is treated as the real
  client address (used for the per-IP layer and for WebSocket upgrade
  limits — the WebSocket guard uses the same helper), and edge-injected region
  headers are believed because the proxy rewrote them from its own verdict.

### Region shaping (`x-geo-region`, `cf-ipcountry`)

Regional multipliers exist to price scarce capacity differently across regions
and to absorb abuse originating from regions with known scripted-traffic
patterns. Because the multiplier both raises and lowers the limit, it must
never be attacker-selectable:

- The value is read **only** from a trusted proxy (`trustedHeader()`); direct
  clients always get multiplier `1`.
- The edge proxy is the authoritative GeoIP source for this decision. The API
  does not perform its own GeoIP lookup: `GEOIP_DATABASE_PATH` is reserved for
  geo labelling of stored data, not for rate-limit policy, and no code path
  derives a limit from it today.
- With no trusted proxy configured, regional shaping is effectively disabled
  (multiplier `1` everywhere).

### Load pressure

There is no `x-system-load` (or any other client-writable) header in the
limit calculation. Load pressure is an **internal signal**:

- Sampled every 10 seconds from the Node event-loop delay
  (`monitorEventLoopDelay`): mean ≥ 500 ms → pressure `0.9`, mean ≤ 20 ms →
  `0.1`, otherwise `0.5`.
- The pressure multiplier is `0.75` above `0.8` (sheds load when the loop is
  saturated), `1.1` below `0.3` (restores headroom when idle), otherwise `1`.
- Operators/load-balancer integrations may override it with
  `setSystemLoadPressure(value)` from internal code; there is no request path
  to it.

Feedback loop: pressure lowers effective limits, request volume drops, the
event loop drains, pressure falls, limits recover on the next 10 s sample.
Because the input is server-side state rather than request content, no client
can push the system into the high- or low-pressure band.
