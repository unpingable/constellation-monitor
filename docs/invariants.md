# Runtime invariants

Status: normative for the initial vertical slice.

These are runtime claim limits, not aspirations. A violation is a defect. The
word "positive" refers only to the `CURRENT` category.

## Evidence and judgment

1. **Receipt is not health.** Admitting a pulse establishes an observation
   occurrence and receiver facts only. No runtime type exposes `healthy=true`.
2. **Positive judgments expire.** Every `CURRENT` judgment depends on evidence
   with a finite receiver-owned expiry. At or after the earliest required
   support expiry, reevaluation cannot return `CURRENT` from that support.
3. **Missingness cannot preserve a positive.** Missing, expired, refused, or
   insufficiently replicated required coverage makes the named reliance
   conditions unsatisfied.
4. **Unknown is not weak health.** `UNKNOWN` makes no positive subject claim.
5. **Adverse findings are sticky by named law.** A negative or contradictory
   record remains visible until explicit resolution, explicit supersession, or
   expiry under a policy rule identified before the transition.
6. **Quorum does not erase contradiction.** Any independently grounded,
   applicable contradiction remains in the evidence model regardless of how
   many other observers agree.
7. **Aggregation preserves gaps.** Every aggregate carries expected, active,
   missing, and expired coverage. A union of positive values cannot omit its
   missingness.
8. **Queueing does not renew evidence.** Retry, buffering, reordering, replay,
   duplicate delivery, or rendering never changes the original admitted
   receiver-arrival time.
9. **Diagnostics are time- and scope-bounded evidence.** A successful
   diagnostic receipt neither creates indefinite health nor silently resolves
   a contradiction.
10. **The monitor observes itself.** Overload, dropped input, receiver-clock
    discontinuity, and transport blindness are confidence dimensions and
    sparse events. They cannot preserve the prior positive judgment.
11. **Escalation cannot mutate.** An escalation requests deeper observation
    only. No request, disposition, receipt, or judgment grants mutation
    authority.
12. **Agents cannot mint profiles or authority.** An agent may select and
    explain a locally predeclared diagnostic profile. It may not introduce a
    command, broaden bounds, change scope, or grant authority.
13. **No scalar replaces evidence dimensions.** The runtime may expose counts
    and durations, but no single confidence score determines or substitutes
    for freshness, continuity, availability, coherence, coverage, provenance,
    transport, and subject-signal consistency.
14. **Judgments are fully indexed.** A present-state judgment names subject
    scope, consumer/reliance class, observation-policy generation, aggregate
    coverage, evaluation time, and evidence-window identity.
15. **Reliance is consumer-specific.** Reusing one evidence window for another
    consumer requires a separate evaluation under that consumer's exact policy.
16. **Policy changes create generations.** Semantic policy changes never edit
    an existing generation in place.
17. **A headline never deletes dimensions.** Category precedence selects the
    most important status label but every applicable adverse dimension and
    reason remains serialized.

## Identity, sequence, and time

18. **Sequence is incarnation-local.** A new observer incarnation starts a new
    sequence lineage. It cannot inherit continuity from the old incarnation.
19. **Older incarnations cannot revive.** After a newer incarnation is
    admitted for an observer, frames from older incarnations cannot become
    current evidence.
20. **Subject restart invalidates old current evidence.** A new subject
    incarnation cannot be described by evidence bound to the prior one.
21. **Duplicate delivery is idempotent.** A repeated sequence within one stream
    cannot refresh evidence, add coverage, erase a gap, or emit another
    equivalent escalation.
22. **Out-of-order delivery cannot replace newer evidence.** A lower sequence
    cannot become the latest evidence or erase a contradiction grounded by a
    later admitted frame.
23. **Gaps are monotone facts.** Later continuity can establish a new
    contiguous suffix but does not rewrite an observed sequence gap as though
    it never occurred.
24. **Receiver time governs freshness.** Sender wall time and observer-local
    monotonic time are provenance only unless a separate named clock
    qualification exists. The initial evaluator has no such qualification.
25. **Clock generations do not mix silently.** Receiver monotonic times are
    comparable only inside the same identified receiver-clock generation.
26. **Expiry is inclusive.** Evidence evaluated at `arrival + validity` is
    expired, not current.

## Coverage, provenance, and contradiction

27. **Policy owns required coverage.** A pulse may admit less coverage than the
    policy expects; it cannot redefine the expectation downward.
28. **Coverage is per occurrence.** A later partial pulse does not retain a
    prior pulse's missing fields as current for that observer.
29. **Authentication is not truth.** Successful authentication establishes
    only the configured provenance check. Failed or absent authentication is
    represented separately and can block consumers that require it.
30. **Observer identity is not independence.** Distinct IDs do not prove
    distinct failure domains. Common-cause uncertainty remains representable.
31. **Contradiction has exact grounding.** Every contradiction record identifies
    the observations, signals, subject incarnation, and policy generation that
    made it applicable.
32. **Resolution is append-only.** Resolving or superseding a contradiction
    appends a lifecycle fact; it does not mutate the original evidence bytes.
33. **No evidence absence is fabricated into a subject violation.** Silence may
    produce `UNKNOWN` or monitoring degradation, never a claim that a subject
    condition itself was observed.

## Escalation and diagnostics

34. **Threshold crossings are causal.** A request identifies the exact
    transition from a previously satisfied reliance bound to an unsatisfied
    one, plus its evidence-window digest.
35. **Equivalent live requests deduplicate.** Repeating the same subject,
    consumer, policy generation, trigger class, and diagnostic profile before
    expiry produces no second execution request.
36. **Expiry does not slide on deduplication or deferral.** Neither event extends
    the original request expiry.
37. **Only registered profiles execute.** The bridge refuses any profile absent
    from its closed registry and accepts no evaluator-supplied program or
    argument vector.
38. **Bounds can only narrow.** A bridge may accept, refuse, defer, or return
    smaller resource bounds. It cannot widen a request.
39. **Expired requests do not execute.** Expiry is checked before diagnostic
    start. A stale accepted disposition is not reusable.
40. **Receipts bind occurrences.** A diagnostic receipt identifies the request,
    causal transition, deduplication key, profile, run, interval, and result
    digest.
41. **Completion does not satisfy pulse policy.** Recording a diagnostic receipt
    alone cannot produce `CURRENT`.

## Encoding, replay, and operation

42. **Pulse wire is compact and bounded.** The high-rate frame uses a bounded
    binary encoding. Decoders reject oversized frames and bounded-field
    violations before evaluation.
43. **JSONL is not the hot wire.** It is limited to fixtures, deterministic
    replay, diagnostics, and sparse durable events.
44. **Replay is deterministic.** The same initial state, policy, trace bytes,
    and evaluation times produce byte-equivalent transition and explanation
    output.
45. **Sparse persistence does not imply pulse retention.** Durable transition
    events contain identities and digests, not an unbounded telemetry history.
46. **Caller input produces typed errors, not panics.** Malformed or unsupported
    records fail closed with bounded reasons.
47. **No unsafe code.** Workspace crates forbid unsafe Rust.
48. **No stronger hostile-trace claim.** For every supplied hostile trace, a
    `CURRENT` result is permitted only when all current policy premises are
    demonstrably present in the encoded trace.

## Maximum stale-positive duration

The runtime recomputes freshness on every ingest and explicit tick. If a
consumer caches the last judgment between ticks, the supported upper bound is:

```text
effective evidence validity + maximum evaluator tick delay
```

The experiment records the observed duration between the earliest required
support expiry and the first non-positive evaluation. This observed value is
`maximum_stale_positive_duration_ms`. It is an experimental measurement, not a
hard real-time guarantee. A run without explicit ticks makes no between-call
latency claim.
