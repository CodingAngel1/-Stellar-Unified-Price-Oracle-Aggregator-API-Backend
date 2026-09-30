# Stellar Price Oracle formal guarantees

This document is the scope statement for the verification gate in CI. It lists
what is checked, what proves it, how to reproduce a check locally, and — most
importantly — what is **not** covered. A claim that is not reproducible from
this document is not a guarantee.

## What is checked

### TLA+ model — `specs/PriceOracle.tla` + `specs/PriceOracle.cfg`

TLC explores a bounded instance of the model and fails on any violation of the
`INVARIANT` (state predicates) and `PROPERTY` (step properties) sets declared
in `specs/PriceOracle.cfg`:

| Claim | Kind | Meaning |
| --- | --- | --- |
| `PriceNonNegative` | invariant | stored prices are non-negative (or absent) |
| `BoundedStorage` | invariant | per-asset history never exceeds `MaxHistoryLen` |
| `HistoryMonotonicTimestamps` | invariant | history timestamps are non-decreasing |
| `LatestMatchesHistory` | invariant | `latestPrice` is exactly the last history entry |
| `InitializedHasAdmin` | invariant | once initialized, the admin is a known admin |
| `NoLossOfFundsStep` | step property | no modeled step moves any balance |
| `AccessControlStep` | step property | no step adds a source unless the caller is the admin |
| `WriteOnceInitializationStep` | step property | the admin never changes after initialization |
| `PriceMonotonicityStep` | step property | a submission never moves an asset's timestamp backwards |

`specs/PriceOracle.cfg` is reviewed input: its constants (`Admins`, `Sources`,
`Assets`, `MaxHistoryLen`, `MaxPrice`, `MaxTime`) bound the state space, so
changing them changes what was actually checked.

### SMT invariants — `verification/smt/price-oracle-invariants.smt2`

Four `(check-sat)` queries; every one must return `unsat`:

1. a submitted price cannot make the stored price negative;
2. a submission cannot move a timestamp backwards;
3. an unauthorized caller and the admin cannot both hold (see gaps);
4. a Merkle leaf hash cannot collide with an internal node hash under the
   domain-separation axiom (issue #566).

### Rust property tests — `contracts/price-oracle/src/fuzz.rs`

Boundary and randomized input tests executed by `cargo test`, including
`fuzz_formal_model_invariants_100k_sequences`, which replays submission
sequences against the model's invariants.

## The gate

`node scripts/generate-verification-report.mjs` writes
`verification/reports/latest.md` and `latest.json`. Every row records the exact
command and git revision that produced it.

| Status | Meaning | Effect on the run |
| --- | --- | --- |
| `PASSED` | the check executed and its assertions held | counted as a pass |
| `FAILED` | the check executed and an assertion did not hold | run fails (exit 1) |
| `NOT CHECKED` | the tool or input was unavailable, so nothing was checked | run fails for required checks; never counted as a pass |

Rules the gate enforces:

- a required check whose tool is missing fails the run instead of being
  silently skipped (`z3`, `java`/TLC, checked-in inputs);
- a skipped check renders as `NOT CHECKED`, never as passed, and the summary
  reports `INCOMPLETE` while any row is unchecked;
- the Rust row is sourced from the workflow step that ran `cargo test`
  (`CARGO_TEST_OUTCOME`) or executed locally with `--cargo`, so it can never
  be reported as passing without a real run;
- tool versions are pinned by SHA-256 in `verification/tools.lock.json` and
  installed by `node scripts/install-verification-tools.mjs`.

In CI the report is uploaded as the `price-oracle-verification-report`
artifact and posted as a pull request comment.

## Reproducing locally

```bash
node scripts/install-verification-tools.mjs   # pinned z3 + tla2tools.jar, checks java
npm run verify:contract                      # cargo test + z3 + TLC + report
```

or step by step:

```bash
z3 verification/smt/price-oracle-invariants.smt2          # 4x unsat
java -jar verification/tools/tla2tools.jar \
  -config specs/PriceOracle.cfg specs/PriceOracle.tla     # no error found
cargo test --manifest-path contracts/price-oracle/Cargo.toml
node scripts/generate-verification-report.mjs
```

## Known gaps

These are out of scope of the current gate. They are stated so that a green
report is not read as more than it is.

- **Bounded, not unbounded.** TLC checks one bounded instance. The claims hold
  for the constants in `specs/PriceOracle.cfg`, not for arbitrary numbers of
  admins, sources, assets, or unbounded prices and timestamps.
- **The model is not the implementation.** There is no refinement check between
  `specs/PriceOracle.tla` and `contracts/price-oracle/src/*`; a contract change
  that contradicts the model is caught only by review.
- **The model is an abstraction.** Staking, slashing, fees, Merkle batch
  verification, upgrades, network partitions and time drift are not modeled.
  `NoLossOfFunds` holds because the modeled steps never move `balances`.
- **The SMT file is hand-written**, not generated from the model or the
  contract. Query 3 is currently a trivial contradiction and therefore proves
  nothing about authorization; it is kept as a placeholder.
- **Property tests sample.** `fuzz.rs` exercises boundaries and random
  sequences; it is not exhaustive and does not prove the absence of overflows
  outside the ranges it covers.
- **No liveness.** The invariants are safety properties; nothing here proves
  that a valid submission is ever observed or that a proposal ever completes.
