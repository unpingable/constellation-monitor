# Receiver-boundary custody campaign reconnaissance

Status: completed read-only on 2026-08-04 before implementation.

## Exact baseline

The standalone repository was clean at exact commit
`94c4c8ee8e7de89edee212abc823e97c809fc26a`, with no configured remote. The
baseline contained seven Rust 2024 crates and 125 passing tests. Formatting and
strict workspace Clippy had passed in the immediately preceding qualified
campaign; the 125-test workspace was rerun successfully before changes.

The README; architecture; receiver/scheduler, crash-fault, and
qualified-generation contracts; campaign-2, campaign-3, and campaign-4
reports; every checked-in demo/qualification artifact; every public
`pulse-types`, evaluator, runtime, reactor, journal, and qualification API; and
all runtime/activation qualification test names and fixtures were inspected.

## Existing custody findings

- A pulse already separates observer, subject and subject incarnation,
  observer incarnation, observation profile and policy generation, monotonic
  sequence, bounded coverage/signals, declared validity, observation digest,
  and a placeholder authentication carrier.
- `ReceiverTracker` owns receiver incarnation, clock identity, monotonic
  arrival, duplicate/replay/gap/restart classification, transport metadata,
  and authentication result. Evaluator freshness is inclusive and anchored at
  that receiver arrival. An optional receiver-verifiable transport delay may
  shorten support; no sender time can lengthen it.
- `ReceiverSchedulerRuntime` accepts `PulseIngressV1`, annotates it locally,
  admits it to every compatible consumer, issues exact support certificates,
  and schedules the earliest support expiry. Queue/observer/stream/history
  saturation latches explicit blindness and removes the positive surface.
- A positive support certificate names the exact local qualified manifest,
  certificate, activation receipt, process occurrence, and runtime generation
  set. It does not yet name remote sender/session/envelope custody.
- `VerifiedActivationV1` and reactor temporal custody are live and
  non-serializable. Current certificates, hot evidence, receiver lineages,
  schedules, request ownership, and active deduplication are ephemeral.
  Sparse events, contradiction custody, activation receipts, and diagnostic
  receipts are historical.
- Restart creates a new process/monotonic epoch and starts
  `Unbound / UNKNOWN` with zero evidence and deadlines. Historical `CURRENT`
  and activation receipts cannot construct live state.
- The append-only journal can custody new sparse receiver-boundary records
  without changing its format or creating a new database. The reactor can
  accept a new move-only remote-evidence input through its existing bounded
  command mailbox.
- Existing `RuntimeConfigV1` is an exact activation-required artifact. A
  backward-compatible optional transport-policy generation and content digest
  can therefore make a typed sender/receiver boundary policy load-bearing
  without changing the ten-role manifest vocabulary or invalidating old
  canonical packages.

No stopping condition was reached. The missing seam is exact live session and
admission custody, not a need to persist standing or trust a sender clock.

## Boundary field allocation

The signed receiver challenge crosses the boundary with receiver key,
process/epoch, nonce, acceptance-policy, intended sender package, expiry and
message/datagram bounds. The signed sender binding crosses with the exact
challenge, sender key/process/epoch, manifest/certificate/activation receipt,
runtime generation set, observer/failure-domain claim, and subject scope. The
signed envelope crosses with those identities, exact subject/incarnation and
sequences, canonical pulse bytes/digest, and sender-local time provenance.

Receiver arrival time, remote endpoint interpretation, replay-window state,
gap classification, queue/rate state, acceptance decision, evidence identity,
evaluation time, coverage interpretation, support deadline, categorical
judgment, escalation, and contradiction applicability remain receiver-local.
No envelope field carries `CURRENT`, health, continuation, transport
administration, diagnostic execution, deployment, signing, revocation, or
mutation authority.

## Bounded neighboring comparison

Only paths already authorized by earlier reconnaissance were rechecked. No
schema, code, cryptographic authority, or network machinery was imported.

| project | exact clean commit | permitted paths/principle rechecked |
|---|---|---|
| NQ-NG | `59abd3bcb2d0cc30657a659b3ebc57b981289d9f` | `docs/NORTH_STAR.md` static-profile cohort and `diagnostic-contract-v2/README.md`: exact identities stay separate from consumer reliance. |
| Witness | `e3d22f9bef8dc248e58e0fa5b7fa474b2dd78c5d` | Existing reconnaissance only: occurrence-local evidence and coverage do not mint standing. |
| Nightshift | `500f4b7bd4f066c7ca43963d192f314559cdbc83` | Existing scheduled/freshness precedent: custody, delay, and retry cannot slide receiver expiry. |
| Docket | `3ce07f9bb3be6ba86ca65f3b521f807970b56119` | Existing normative packet precedent: authenticated or historical facts do not reconstruct current authority. |
| Synesthesia | `d1a731c383d4fce8f9bc21f40b63af5dbae2aa94` | Existing ingestion precedent: bounded queues and loss/conflict must remain visible. |

All five neighboring worktrees were clean before the recheck. None was
modified.

## Live-host finding

The local machine is Linux. The sole explicitly configured non-Git SSH peer
was reachable with the configured key but reported Darwin, not Linux. No
second explicitly configured and authorized Linux host was discoverable. The
campaign may therefore qualify real local UDP behavior and process crashes,
but an actual two-Linux-host exercise remains unexecuted and cannot be claimed.
Exact hostnames belong only in the final report/machine artifact.

## Authentication choice

The locally cached maintained library `ed25519-dalek` 2.2.0 provides Ed25519,
strict verification, default zeroization for signing keys, and forbids unsafe
code in its own crate. Campaign code will use `verify_strict`, distinct
length-framed signature domains, exact pinned public keys, and no legacy or
hazardous features. Signature validity is only configured-key possession over
exact bytes; it is not signer authority, key secrecy, host identity, or remote
attestation.
