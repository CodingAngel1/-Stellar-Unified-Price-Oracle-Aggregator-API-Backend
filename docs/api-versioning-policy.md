# API versioning policy

The service supports a dual-version strategy where v2 is the current stable contract and v1 remains in maintenance mode.

## Policy

- `v2` is the current stable version.
- `v1` remains available for compatibility but is deprecated and carries deprecation headers on responses.
- The migration guide is the canonical source for consumers moving from v1 to v2.
- The sunset date is defined in the versioning middleware and should remain in sync with release notes and migration docs.

## Headers

v1 responses include the following:

- `Deprecation`
- `Sunset`
- `Link: <...>; rel="deprecation"`
- `X-API-Version: v1`

v2 responses include:

- `X-API-Version: v2`

This keeps the deprecation path explicit while preserving a clean upgrade path for integrators.

## GraphQL (preview)

GraphQL (`POST /graphql` and `POST /api/graphql`) is a **preview** surface, not
a stable contract:

- It is disabled by default. `GRAPHQL_ENABLED=true` is required; without it the
  endpoint answers `403 GRAPHQL_DISABLED`.
- It runs behind the same API-key authentication, per-key rate limiting and
  usage tracking as REST, so it cannot bypass rate limiting or usage metering.
- It is gated by tier (`GRAPHQL_ALLOWED_TIERS`, default `pro,enterprise`); other
  tiers get `403 GRAPHQL_TIER_FORBIDDEN`.
- Queries are bounded by `GRAPHQL_MAX_DEPTH` (default 5) and
  `GRAPHQL_MAX_COMPLEXITY` (default 100, where a field costs 1 plus its `limit`
  argument capped at `GRAPHQL_MAX_LIMIT`). `limit` is clamped to the same
  maximum page size REST uses (default 25) and is rejected above it.
- Every query has a `GRAPHQL_TIMEOUT_MS` budget (default 5000); exceeding it
  returns `504 QUERY_TIMEOUT`.
- Introspection is off unless `GRAPHQL_INTROSPECTION=true`.
- Resolvers read the same price store and share the same cache as the REST
  routes, and responses carry `X-API-Version: preview`.

Because the schema may change without notice, no compatibility is promised
until GraphQL is promoted to a versioned endpoint.
