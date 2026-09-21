# Hostile scenario corpus

Status: normative expected behavior for the initial replay corpus and local
crash-fault qualification corpus.

Every trace is JSONL and supplies explicit logical receiver times. Replay uses
no ambient wall clock. A repeated run must produce byte-equivalent semantic
transitions and explanations.

## Trace scenarios

| trace | hostile condition | required result |
|---|---|---|
| `packet-loss.jsonl` | supporting pulses stop | prior `CURRENT` expires to `UNKNOWN`; loss is not subject failure |
| `duplication.jsonl` | one frame is repeated | duplicate count rises; coverage and freshness do not refresh |
| `reordering.jsonl` | a lower sequence follows a newer contradictory frame | old frame is rejected for current state and cannot erase contradiction |
| `delayed-stale-delivery.jsonl` | an already-seen old frame arrives after expiry | stale/replay drop count rises and status is not restored |
| `sequence-gap.jsonl` | sequence jumps | exact gap is recorded and continuity degrades |
| `observer-restart.jsonl` | observer incarnation changes and sequence restarts | new lineage is `RESTARTED`; old continuity is not inherited |
| `subject-restart.jsonl` | observers cross subject incarnations | old subject evidence cannot cover the new incarnation; disagreement is retained |
| `clock-discontinuity.jsonl` | receiver clock generation becomes unusable | monitoring blindness is exposed and positive reliance is withdrawn |
| `network-partition.jsonl` | every observer becomes silent | coverage expires to `UNKNOWN` within the configured validity/tick bound |
| `observer-disagreement.jsonl` | observers report incompatible signal assessments | `CONTRADICTED`; a later majority does not clear the record |
| `stale-replay.jsonl` | valid old bytes are replayed after a newer incarnation/sequence | bytes remain historical only; no current restoration |
| `common-cause-failure.jsonl` | several IDs share a declared failure domain and disappear together | no independence claim; coverage collapse and `UNKNOWN` remain explicit |
| `monitor-overload.jsonl` | receiver reports input loss/overload | transport/monitor dimension becomes blind and no stale positive is preserved |
| `coverage-collapse.jsonl` | pulses continue with required fields removed | active versus expired coverage is shown; result is `UNKNOWN` |
| `lying-self-report.jsonl` | subject self-report stays within bound while an external observer reports a violation | contradiction is preserved; self-report does not win by continuity |
| `escalation-storm.jsonl` | equivalent failures repeat | one active request is emitted; later equivalents increment deduplication |

The demo trace is separate from the hostile corpus and shows normal evidence,
divergence, escalation, diagnostic receipt correlation, and continued caution.

## Required properties

1. A previously positive judgment expires after pulse loss.
2. Delayed packets cannot restore current status.
3. Reordered packets cannot erase a newer contradiction.
4. A restarted observer does not silently inherit sequence continuity.
5. Majority agreement does not erase an independently grounded contradiction.
6. Incomplete coverage cannot aggregate into an unconditional positive state.
7. A degraded evaluator reports monitoring blindness rather than preserving
   subject confidence.
8. Repeated equivalent failures deduplicate escalation requests.
9. Escalation expiry prevents stale diagnostics from executing.
10. Diagnostic completion updates the evidence model but does not establish
    indefinite health or even immediate `CURRENT` by itself.
11. The evaluator never grants mutation authority.
12. No hostile trace produces a claim stronger than the evidence encoded in
    that trace.

## Property-based test domains

Property-based tests permute:

- lower delivery sequences after an arbitrary accepted high-water sequence;
- arbitrary duplicate multiplicity and pre-expiry duplicate arrival times;
- arbitrary validity bounds and evaluation overshoot at inclusive expiry; and
- observer-incarnation changes with arbitrary sequence resets.

Generated ordering cases are replayed twice to check deterministic output.
Subject-incarnation disagreement, repeated equivalent escalation triggers, and
the remaining named faults use deterministic corpus tests rather than claiming
broader generated coverage.

The oracle is not a scalar expected score. It asserts the invariants: old
evidence never replaces newer, expiry is inclusive, a new incarnation never
inherits continuity, unresolved contradiction remains blocking, and identical
replay produces identical output.

## Normal-trace false escalations

The corpus includes an all-normal control path. Its expected false escalation
count is zero. This is a supplied-fixture measurement, not a general
false-positive rate.

## Limits of hostile validation

The corpus does not establish Byzantine correctness, production load capacity,
network-clock qualification, cryptographic authenticity, or hard real-time
latency. In particular, it cannot detect a first-seen packet delayed entirely
before receiver arrival without additional evidence. The trace must encode a
known prior sequence, a receiver-verifiable delay fact, or a later expiry for
the delayed-delivery property to apply.

## Local crash-fault corpus

The reactor/journal campaign adds real-thread and Linux child-process cases
outside JSONL replay:

- autonomous inclusive expiry, early notification/re-arm, deliberate late
  wakeup, multiple earliest-first deadlines, generation cancellation, mailbox
  saturation, journal exhaustion, actor unwind, owner abandonment, and clean
  shutdown;
- `SIGKILL` before/after deadline arming, before expiry, after in-memory
  withdrawal but before journaling, after frame write before sync, after commit
  sync before acknowledgement, during header/payload/trailer writes, after
  acknowledged contradiction and escalation-dedup custody, and during clean
  shutdown;
- clean and empty journals, partial header/payload/trailer/commit writes,
  uncommitted suffixes, duplicate/stale/reordered/skipped frames, oversized
  declared length, unsupported version/kind, interior and first-record bit
  corruption, unexpected trailing bytes, bounds, and injected append I/O
  failure; and
- truncation at all 3,088 byte positions of a three-record corpus. No partial
  frame becomes a record. Truncation at zero or another exact committed-prefix
  boundary is indistinguishable from a legitimately shorter self-contained
  journal and is retained as a named limitation.

Every restart oracle is independent of journal health:

```text
current standing = UNKNOWN
supporting evidence = 0
active deadlines = 0
mutation authority = none
```

A `RecoveredThroughValidPrefix` result is explicitly incomplete and carries
operator action. A `Refused` result cannot project runtime history. Later
valid-looking bytes after interior corruption are never scanned as records.

## Receiver-boundary custody corpus

The bounded transport campaign adds generated and integration cases for:

- exact offer/challenge/binding/receiver-acceptance/envelope handshake and
  distinct Ed25519 domains;
- wrong keys, same-label receiver-policy substitution, signature mutation, package/activation/process/observer/
  failure-domain/receiver/subject/incarnation/session substitutions;
- every byte truncation and every single-byte corruption across a small
  five-message corpus, trailing bytes, noncanonical policies, and 128 bounded
  arbitrary datagrams;
- duplicate envelope, duplicate observation under a fresh envelope, repeated
  duplicate multiplicity, replay, reorder, explicit sequence gap and gap-bound
  refusal, old challenge, session/rate exhaustion, session expiry, queue
  saturation, bounded sender emission, and competing occurrence;
- receiver-owned silence expiry, explicit partition without invented subject
  contradiction, different consumer judgments, and observation-time
  freshness refusal under first-seen delay; and
- real Linux `SIGKILL` while remote evidence is `CURRENT`, followed by journal
  recovery with `Unbound / UNKNOWN`, no session, evidence or deadline.

An actual UDP loopback probe verifies exact datagram preservation but is
explicitly not a two-host result. No authorized second Linux host was
available, so cross-host timing, packet-loss and restart obligations remain
unexecuted rather than simulated.
