# Local crash-fault campaign reconnaissance

Status: completed read-only on 2026-08-03 before campaign implementation.

## Baseline

The standalone repository was clean on `main` at exact commit
`668589e537e9cffe151913f72ca45a61ca32b1d7`, with no configured remote. Its
history ended in the three receiver/scheduler campaign commits. The baseline
passed:

```text
cargo fmt --all -- --check                                      PASS
cargo clippy --workspace --all-targets --all-features -- -D warnings PASS
cargo test --workspace --all-targets --all-features            PASS (73)
```

The README, architecture, runtime contract, campaign-2 report, every checked-in
qualification/demo artifact, all `pulse-runtime` source, its public API, and
all 30 runtime qualification tests were inspected.

## Existing runtime findings

- `ReceiverSchedulerRuntime::run_until(now)` merges due pending inputs and due
  schedules under a stable total order. At one logical instant, context and
  subject barriers precede inclusive expiry, which precedes pulses and later
  reevaluation. It calls evaluator `tick(actual_now)` and records deadline
  overshoot; no actor currently owns calling it.
- Current judgments live only in each in-memory `ConsumerState.certificate`.
  Hot evaluator evidence, the receiver tracker, pending inputs, schedules,
  request ownership, and active evaluator escalation deduplication are also
  ephemeral.
- `RuntimeHistoricalStateV1` serializes sparse events, contradiction custody,
  and diagnostic receipts. A sparse event may truthfully contain a certificate
  that was historically `CURRENT`; the history type has no current projection,
  deadline, pulse window, or receiver lineage.
- Recovery creates a new receiver incarnation and clock generation, registers
  new exact activations, imports only applicable active contradictions, and
  emits `UNKNOWN` with zero current evidence and zero schedules.
- Contradiction custody retains immutable records plus consumer applicability.
  Diagnostic disposition and completion do not alter contradiction lifecycle.
- Escalation deduplication is evaluator-local and active only until the exact
  request expiry. Sparse events retain request and dedup occurrences, while
  `request_owners` and suppression state are not historical state.
- Runtime timestamps assume one caller-supplied receiver clock generation.
  Regression within it latches blindness. There is no type yet binding a
  persisted timestamp to a process-local `Instant` epoch, and no comparison
  across restart is lawful.
- Sparse-history exhaustion already fail-stops admission. Filesystem append,
  framing, sync, torn-write detection, and corruption recovery are absent.

No stopping condition was reached. The existing current/history split is
sufficient for a journal that never reconstructs present standing.

## Permitted donor recheck

Only concepts and paths already authorized by the repository's prior
reconnaissance were compared. No source, schema, or runtime machinery was
copied.

| project | exact inspected commit | bounded comparison |
|---|---|---|
| NQ-NG | `59abd3bcb2d0cc30657a659b3ebc57b981289d9f` | Commit and cleanliness rechecked; independent exact identities remain the only relevant principle. |
| Witness | `e3d22f9bef8dc248e58e0fa5b7fa474b2dd78c5d` | Commit and cleanliness rechecked; occurrence-local coverage remains separate from durable standing. |
| Nightshift | `500f4b7bd4f066c7ca43963d192f314559cdbc83` | Previously named `scheduled.rs`, `freshness.rs`, tolerability-horizon flow, and NQ reliance source: receiver custody and expiry do not slide freshness or create retries. |
| Docket | `3ce07f9bb3be6ba86ca65f3b521f807970b56119` | Previously named normative packet and Continuity seam: immutable history is distinct from current projection; replay does not apply authority; expired standing does not revive. |
| Synesthesia | `d1a731c383d4fce8f9bc21f40b63af5dbae2aa94` | Previously named design and ingestion surfaces: bounded queues and distinct loss classes must remain visible. |

All five donor trees were clean before and after the read-only recheck. No
neighboring repository was modified.
