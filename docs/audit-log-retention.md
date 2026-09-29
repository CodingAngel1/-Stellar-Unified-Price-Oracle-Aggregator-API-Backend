# Audit log retention and tamper evidence

This policy defines how operational audit logs are retained and verified.

## Retention policy

The API enforces a configurable retention window for audit logs. The default operational policy is 90 days; the compliance dashboard keeps a longer archive window for supporting evidence and subject-access workflows.

For the production compliance configuration, the system uses the following default retention logic:

- audit logs: 90 days in active storage
- archive retention: 3 years for governance and incident evidence
- debug and raw payload logs: 90 days, then deletion

The actual retention implementation lives in `api/src/governance/audit-logger.ts` and is enforced on every new audit entry. Retention prunes a prefix of the file, which is why the first line of a log is allowed to anchor to history that no longer exists.

## Tamper-evident chain

Each entry carries:

- `hmac` — SHA-256 HMAC over a canonical serialisation of the entry plus its
  `prevHmac`;
- `prevHmac` — the hmac of the previous entry **written by the same writer**;
- `writerId` — identifies the replica/process that wrote the entry;
- `seq` — that writer's monotonic sequence number, contiguous per writer;
- `keyId` — the id of the signing key that produced the hmac.

Entries are grouped by `writerId`. Verification (`verifyAuditLogChain`) checks,
for every writer: sequence numbers are contiguous, each `prevHmac` equals the
previous entry's `hmac`, and every hmac recomputes. The first entry of a
writer's chain must anchor to an entry that already appears earlier in the same
file (anchors are irrelevant only for the very first line, whose history may
have been pruned).

### Security property that actually holds

Under concurrent writers the guarantee is:

> Any modification of, or removal from, the interior of a writer's chain is
> detected, and no writer can append an entry that is not linked to its own
> prior chain.

What is **not** claimed:

- there is no single total order across replicas — interleaving order in the
  file is not authenticated, only per-writer order is;
- deleting an entire writer's chain is detected only when a later entry still
  anchors to it;
- the log is tamper-*evident*, not tamper-*proof*: an attacker with write
  access to the whole file could recompute it if they also obtain the signing
  key (see below).

## Secret management and rotation

- `AUDIT_SECRET` is mandatory when `NODE_ENV=production`; startup fails
  otherwise. There is no default key — outside production an ephemeral
  per-process key is generated, so no shared, guessable key exists anywhere.
- Rotate by setting `AUDIT_SECRET` to the new value and moving the old value to
  `AUDIT_SECRET_PREVIOUS`. Every entry records `keyId`, so historical entries
  stay verifiable after rotation.
- Keying is per entry: an entry signed with an unknown `keyId` fails
  verification instead of being silently accepted.

## Automatic verification

- `initializeAuditIntegrity()` runs at startup: it loads the keyring, verifies
  the existing log, and seeds the writer chain from the last entry.
- If the chain cannot be verified, nothing is appended to it. The broken log is
  preserved under a new file for forensics and a fresh chain is started; set
  `AUDIT_CHAIN_ON_BREAK=throw` to refuse startup instead.
- `startAuditChainVerification()` re-verifies on a schedule
  (`AUDIT_CHAIN_VERIFY_INTERVAL_MS`, default 1 hour, `0` disables) and records
  the result.

Alerting is metric-based:

| Metric | Meaning |
| --- | --- |
| `audit_chain_valid` | `1` while the active log verifies, `0` after a break or fork |
| `audit_chain_verifications_total{result}` | `passed`, `failed`, `forked`, `error` |
| `audit_events_total{result}` | `appended` or `refused` (no signing key) |

`result="failed"` or `audit_chain_valid 0` should page.

## Durability across replicas

- Every entry is written to the audit file (`AUDIT_LOG_FILE`, default
  `logs/audit.log`) **and** to stdout as a single JSON line unless
  `AUDIT_STDOUT=false`. Point stdout at the platform's log shipper so records
  outlive the pod; give each replica its own `AUDIT_LOG_FILE` when volumes are
  not shared.
- Because chains are per writer, replicas appending to a shared file interleave
  safely: verification groups by `writerId` instead of failing at the first
  handover.

## Verification workflow

1. Export a complete log file or journal slice.
2. Run `verifyAuditLogChain(entries)` (or rely on the scheduled check).
3. Treat the first invalid index as a tamper indicator and quarantine the file
   for forensic review.

This workflow can be used to satisfy audit and incident-review requirements without introducing a new operational dependency on an external attestation service.
