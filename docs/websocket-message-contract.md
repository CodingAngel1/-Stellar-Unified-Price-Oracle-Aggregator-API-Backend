# WebSocket message contract

Reference for the price streaming socket (`WS_PORT`, default 3001): message
types, subscription semantics, sequence numbering under filtering, and replay.

## Connection

```
ws://host:WS_PORT
headers: x-api-key: <key>          (or Authorization: Bearer <key>)
         origin: <any>             (required unless WS_REQUIRE_ORIGIN=false)
```

The server replies with `connected`:

```json
{ "type": "connected", "clientCount": 3, "sequenceId": 4120, "replaySupported": true, "bufferSize": 200, "subscriptionRequired": true }
```

## Subscriptions are mandatory for delivery

A connection starts with an empty subscription set and **receives no
`price_update` frames until it subscribes**:

```json
{ "type": "subscribe", "assets": ["XLM", "USDC"] }
{ "type": "subscribed", "assets": ["XLM", "USDC"], "sequenceId": 4121 }
{ "type": "unsubscribe", "assets": ["XLM"] }
{ "type": "unsubscribed", "assets": ["XLM"] }
```

- Up to 50 assets per message, uppercase or lowercase input (stored uppercase).
- Delivery rule: a frame is sent only when the client's subscription set is
  non-empty **and** contains the frame's asset. Everything else is dropped for
  that client and counted in `ws_api_client_messages_total{result="dropped"}`.

### Is subscription an access-control boundary?

**No — it is a delivery filter, documented here as such.** The authorisation
boundary is the API key: every authenticated key may read every asset the
service publishes, so subscribing grants no visibility it did not already have.
Replay is scoped to the same subscription set (below), which limits *traffic*,
not *knowledge*. If per-key asset scopes are ever introduced they must be
enforced in `subscribe` **and** `replay`; until then this contract explicitly
states that asset visibility is not key-dependent.

## Sequence semantics under filtering

`sequenceId` is a **global, monotonic** counter shared by every asset and every
client. Delivery is per-client filtered, so a filtered client sees a strictly
increasing but *sparse* subsequence of the global counter.

| Observation | Meaning |
|---|---|
| `sequenceId` jumps between two delivered frames | The missing numbers belong to assets this client is not subscribed to (or to frames broadcast before this client subscribed). This is normal, not data loss. |
| `sequenceId` decreases or repeats | Protocol violation — reconnect. |
| "Am I caught up?" | Use `replay_complete`, not raw sequence arithmetic: it is the authoritative receipt for *your* scope (below). |

Because gaps are legitimate, clients must not infer loss from a gap alone.
Frames buffered per asset are retained up to `WS_BUFFER_SIZE` entries (default
200).

## Replay

```json
{ "type": "replay", "lastSequenceId": 4121, "assets": ["XLM"] }
```

Replay is **scoped to the connection's subscriptions**:

- `assets` omitted → every subscribed asset is replayed from `lastSequenceId`.
- `assets` provided → only the intersection with the subscription set is
  replayed; assets you never subscribed to are silently excluded.
- No subscriptions → nothing is replayed.

```json
{ "type": "replay_complete", "replayed": 4, "sequenceId": 4310, "assets": ["XLM"], "scope": "subscriptions" }
```

- `replayed` — number of frames sent for this request.
- `assets` — the scope actually applied (after subscription filtering).
- `sequenceId` — current global head; replayed frames all have
  `sequenceId <= ` this value.
- `scope` is always `"subscriptions"`.

## Metrics

| Metric | Labels | Meaning |
|---|---|---|
| `ws_api_client_messages_total` | `client`, `result=delivered\|dropped` | Per-connection fan-out outcome. A client that never subscribes shows only `dropped`. |
| `ws_api_client_subscriptions` | `client` | Current subscription count for a connection; `0` means it receives no price frames. Series are removed on disconnect. |
| `ws_api_subscribe_events_total` | `action=subscribe\|unsubscribe` | Subscription churn. |
| `ws_api_messages_total` | `direction`, `type` | Raw message counters. |

`client` is a short per-connection id, removed on disconnect to bound label
cardinality.
