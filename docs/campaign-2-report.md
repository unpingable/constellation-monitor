# Bounded receiver/scheduler campaign report

Status: qualified locally on 2026-08-03. Repository and crate names remain
provisional.

## Baseline and isolation

The campaign began from exact commit
`0a9fe16e6d091c6b4b1128fcb6166e53d712fc3f` on `main`, with a clean tree and
no configured remote. The five neighboring donor repositories were inspected
only at the paths and commits recorded in
[campaign-2-reconnaissance.md](campaign-2-reconnaissance.md). No neighboring
repository was modified, no remote was created, and nothing was pushed.

The final commit is intentionally reported by the repository handoff rather
than embedded here: a commit cannot contain its own hash.

## Implemented semantic kernel

The new `pulse-runtime` crate is a bounded, single-process owner around the
existing receiver and per-consumer evaluator. It provides:

- hard subject, consumer, observer, stream, observer-incarnation,
  subject-incarnation, pending-input, deadline, context-history, active
  escalation, certificate-reference, sparse-history, and receipt bounds;
- deterministic same-instant order from stable semantic identities, with an
  ingress ordinal only as the final exact-duplicate tie-breaker;
- receiver-owned evaluation time and one exact earliest-expiry schedule for
  every issued `CURRENT` certificate;
- an exact `RelianceContextV1` binding reliance-policy generation and body,
  consumer-profile generation, evaluator-semantic generation, observer-set
  generation, observation-policy generation, and a single-use activation;
- a mandatory `UNKNOWN` barrier on every relevant generation or subject
  transition, followed by separate explicit evidence reevaluation;
- bounded support certificates naming subject incarnation, exact context,
  evidence window and references, missing premises, applicable
  contradictions, coverage, expiry/next evaluation, escalation state, and
  structural no-mutation authority;
- typed, sparse refusal/degradation records and fail-closed behavior for
  queue/cardinality/custody exhaustion and clock regression;
- history-only serialization/recovery for sparse events, contradiction
  custody, and diagnostic receipts, with no hot pulse, receiver lineage,
  schedule, escalation lease, or authoritative current projection;
- narrow contradiction inapplicability only for explicit configured subject
  replacement under `subject_incarnation_replacement/v1`; and
- diagnostic requests and receipts that now bind observation-policy
  generation separately from consumer reliance-policy generation.

The runtime remains driven by an explicit local reactor call. It owns the
deadline and exposes the next deadline; the caller supplies the monotonic wake
occurrence. This is not a production scheduler.

## Exact claims earned

The checked tests and artifacts earn only these campaign claims:

1. With a runtime wake at or after an exposed support deadline, no new pulse is
   required to withdraw an expired `CURRENT`; inclusive expiry is enforced.
2. Scheduler delay never moves support expiry. The runtime records the actual
   overshoot, including when an earlier queued input is processed after the
   deadline.
3. A new exact activation first produces non-inherited `UNKNOWN`, even for a
   looser policy, equal-content generation, rollback body, ABA return,
   evaluator-semantic change, observer-set change, or subject replacement.
4. Old compatible evidence can be reconsidered only by a separate evaluation,
   and any re-earned certificate names the new exact activation and generation
   set.
5. A transition for one consumer does not modify another consumer's context,
   certificate, or schedule.
6. Stable same-instant ordering is independent of enqueue order for distinct
   policy/expiry events and pulse transcripts tested by the property harness.
7. Duplicate, replayed, reordered, and stale pulse occurrences cannot renew
   receiver-owned freshness.
8. Queue, observer, subject, schedule-reservation, subject-incarnation, and
   sparse-history bounds refuse explicitly; observation loss cannot leave a
   cached positive standing in place. Monitor restoration itself remains
   `UNKNOWN` until a separate reevaluation.
9. Equivalent active escalation requests deduplicate across repeated
   reevaluation without sliding expiry.
10. Diagnostic disposition and receipt processing uses receiver evaluation
    time; completion does not clear an active contradiction, refresh pulse
    evidence, or grant mutation authority.
11. Active contradiction custody survives policy transitions and restart.
    Old-incarnation inapplicability survives recovery/re-export as history.
12. An exact serialized history can contain a historical `CURRENT`
    certificate record while recovery starts with `UNKNOWN`, zero supporting
    evidence, and zero scheduled deadlines. Receipt custody also recovers
    without clearing contradiction.
13. A historical reliance-policy generation cannot be rebound to different
    semantic content after restart.
14. The same evidence can still lawfully produce different judgments for two
    consumers.

The bounded earned result is therefore conditional: when the local reactor is
invoked within a named scheduling delay, the runtime detects that current
reliance premises ceased to hold, preserves the reason, and may emit one
bounded diagnostic request. It does not establish a scheduler-delay guarantee.

## Exact nonclaims

This campaign does not establish subject health, observation truthfulness,
complete coverage, independent observers, Byzantine correctness, production
scheduler or network reliability, hard real-time behavior, crash-durable
current standing, qualified persistent storage, authority to continue
operation, authority to mutate, automatic remediation, full contradiction
resolution, deployment viability, or product-plane/category status. It does
not qualify a generic transport, collector, scheduler, agent API, rules engine,
or observability platform.

## Qualification results

The final source passed:

```text
cargo fmt --all -- --check                                      PASS
cargo clippy --workspace --all-targets --all-features -- -D warnings PASS
cargo test --workspace --all-targets --all-features            PASS (73 tests)
```

The 73 tests comprise the preserved hostile/replay/type/agent/bridge suite and
30 runtime campaign tests, including five property tests over duplication,
generation churn, same-instant ordering, and observer identity churn. The
machine-readable case index is
[`runtime-qualification.json`](../artifacts/runtime-qualification.json).

## Deterministic demonstrations

`cargo run -p pulse-runtime -- demo` produced:

```text
[000ms] UNKNOWN policy:p1 / activation:p1-first
[010ms] CURRENT policy:p1 / activation:p1-first; deadline=50ms
[020ms] UNKNOWN policy:p2 / activation:p2; equal body, inherited=false
[030ms] UNKNOWN policy:p1-body-rollback-g3; rollback, no resurrection
[031ms] CURRENT policy:p1-body-rollback-g3; explicit reevaluation; deadline=50ms
[050ms] UNKNOWN policy:p1-body-rollback-g3; inclusive expiry, no new pulse
```

It emitted one bounded escalation at expiry and measured deterministic
`maximum_stale_positive_duration_ms = 0`. The exact record is
[`runtime-generation-demo.json`](../artifacts/runtime-generation-demo.json).

`cargo run -p pulse-runtime -- restart-demo` serialized 5 sparse records
(6,461 bytes), recovered one historical `CURRENT` certificate record exactly,
and produced:

```text
historical records recovered: 5
current standing: UNKNOWN
current supporting evidence: 0
scheduled deadlines: 0
standing recovered: false
```

See [`runtime-restart-demo.json`](../artifacts/runtime-restart-demo.json).

## Bounded live Linux exercise

The checked-in run of `cargo run -p pulse-runtime -- live-linux` used local
Linux `/proc` coverage `proc.cpu` and `proc.memory` and measured:

| measurement | observed value |
|---|---:|
| expected support-expiry deadline | 61 ms |
| actual reevaluation | 76 ms |
| stale-positive overshoot | 15 ms |
| policy-transition withdrawal, wall observation | 851 us |
| policy-transition withdrawal, logical clock | 0 ms |
| duplicate escalation count | 1 |
| recovered sparse records | 20 |
| receiver restart standing | `UNKNOWN` |
| queue saturation | `pending_queue_capacity` refusal |
| observer saturation | `observer_capacity` refusal |

These are one-process wall measurements, not limits or hard real-time
guarantees. They are deliberately separate from deterministic replay-clock
results in [`runtime-live-linux.json`](../artifacts/runtime-live-linux.json).

## Hostile scenarios covered

The combined corpus covers inclusive expiry; deadline overshoot; delayed
scheduler processing; queue, observer, subject, deadline, subject-incarnation,
and sparse-history saturation; duplicate multiplicity; reordering and replay;
observer and subject restart; receiver restart; clock regression; policy
tightening and loosening; equal-content regeneration; rollback; ABA;
consumer-isolated transitions; consumer-profile, evaluator, observer-set, and
observation-policy generation changes;
same-instant transition/expiry and pulse ordering; historical generation
rebind; common-cause observers; monitor overload; coverage collapse; stale
self-report; contradiction under majority agreement; diagnostic storms;
expired escalation; delayed disposition; receipt persistence; and
contradiction non-laundering through completion, replacement, and restart.

## Findings and known gaps

- No stopping condition was reached. Identity/content separation, history-only
  recovery, total event order, explicit bounds, and narrow contradiction
  custody were implementable without changing a neighbor.
- The live exercise exposed one real modeling bug: an allowed provenance
  caution had been mislabeled as a missing premise. The certificate builder now
  distinguishes a nonblocking caution from an unsatisfied named premise, with
  a regression test.
- The reactor has no background timer thread, OS scheduling qualification,
  multi-process failover, or network transport. Failure to call `run_until`
  remains measured scheduler lateness, not a bounded deployment guarantee.
- `RuntimeHistoricalStateV1` has an exact serialization/recovery contract but
  no atomic file journal, `fsync` policy, torn-write handling, corruption
  proof, retention compaction, or authenticated storage.
- Consumer-profile, evaluator-semantic, and observer-set generations are exact
  invalidation identities. This campaign does not load alternate evaluator
  binaries or prove that external configuration content matches those names.
- Contradiction policy supersession beyond explicit resolution and the one
  subject-replacement rule remains intentionally unimplemented.
- Authentication remains a result carrier/placeholder. First-seen one-way
  network delay, observer independence, and truthful coverage remain unknown.
- Capacity choices are qualification constants, not production sizing, and
  refusal can intentionally sacrifice availability to avoid false confidence.

No previously earned invariant was falsified. The provenance-caution issue was
an unqualified path added by the live campaign and was fixed before claiming
the live result.

## Lawful conceptual reuse

The campaign reused only principles already recorded by reconnaissance:
NQ-NG's independent semantic/build generation identities; Witness's
occurrence-local partial coverage; Nightshift's receiver-owned expiry and
non-sliding retry posture; Docket's distinction between immutable history and
current projection plus ABA sensitivity; and Synesthesia's bounded queues and
visible loss counters. The runtime records, activation law, certificate,
scheduler order, and contradiction applicability are native to this repository
and were not copied from donor schemas.

## Category assessment and next campaign

The result remains a **useful runtime component**. It is more than a visual
restatement of ordinary monitoring because exact consumer-indexed standing,
non-inheriting generation barriers, contradiction custody, and expiring support
certificates are executable semantics. It still does not justify stronger
present-confidence product-plane language: there is no qualified reactor,
durable custody implementation, network boundary, operational integration, or
evidence of product demand.

The single most defensible next campaign is a **local crash-fault reactor
qualification**: add one real monotonic timer/wakeup loop and one bounded
append-only history adapter with atomic generation activation, then inject
late wakeups, process kills, torn final records, restart, and clock-generation
replacement. Keep transport local and retain the no-remediation boundary.
