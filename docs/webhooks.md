# Webhooks: registration, signing and verification

Every delivery is signed with an HMAC that the consumer can verify against
material the API actually publishes. This document is the contract for that
material.

## Registration and the secret

`POST /api/v1/webhooks` returns `201` with:

| Field | Meaning |
|---|---|
| `secret` | Per-registration HMAC key (32 random bytes, hex). **Returned once**, in this response only. |
| `secretReturnedOnce` | Always `true`. |
| `signature.algorithm` | `HMAC-SHA256` |
| `signature.header` | `X-Webhook-Signature` |
| `signature.format` | `sha256=<lowercase hex>` |

The secret is derived per registration with `crypto.randomBytes`. There is no
environment-wide signing secret and no default value: an unconfigured
environment still produces a unique, random secret per webhook. `GET
/api/v1/webhooks`, `GET /api/v1/webhooks/{id}` and the delivery log never
include the secret. If you lose it, rotate by deleting and re-registering the
webhook.

## Signature semantics

```
body   = JSON.stringify({ webhookId, ...payload })     // no spaces, exactly as sent
sig    = "sha256=" + hex(HMAC-SHA256(secret, body))
header = X-Webhook-Signature: <sig>
```

- The signature covers the **raw request body bytes** (UTF-8). Verify the bytes
  you received; never re-serialise the parsed JSON first, because key order and
  whitespace would change the digest.
- Additional headers: `X-Webhook-Id` (the registration id) and
  `X-Webhook-Timestamp` (unix seconds).
- Compare with a timing-safe equality (`crypto.timingSafeEqual`).

## Verification recipe

```js
import crypto from 'crypto';

function verify(secret, rawBody, headerValue) {
  const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  const a = Buffer.from(expected);
  const b = Buffer.from(String(headerValue));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
```

`GET /api/v1/webhooks/verification-key` publishes this scheme (algorithm,
header, format, signed-payload semantics, recipe) plus the test vector below.
It never returns key material.

## Test vector

Use this to self-test your implementation before trusting it in production:

| Input | Value |
|---|---|
| `secret` | `test-secret-0000000000000000000000000000` |
| `body` | `{"webhookId":"00000000-0000-4000-8000-000000000001","asset":"XLM","price":0.42,"timestamp":1700000000}` |
| `signature` | `d285bbf58d70eff02a911f8bc9d9ce12592898054e5b52f868f7b1b53844c081` |
| header value | `sha256=d285bbf58d70eff02a911f8bc9d9ce12592898054e5b52f868f7b1b53844c081` |

The conformance test in `api/tests/webhook-verification-material.test.ts`
recomputes this vector and also verifies a real delivery against the material
advertised by `GET /verification-key`, so the endpoint and the signer cannot
drift apart again.
