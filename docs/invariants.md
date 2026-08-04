# Runtime invariants

Status: normative for the qualified vertical slice, bounded runtime, local
reactor, and historical journal.

These are runtime claim limits, not aspirations. A violation is a defect. The
word "positive" refers only to the `CURRENT` category.

## Evidence and judgment

1. **Receipt is not health.** Admitting a pulse establishes an observation
   occurrence and receiver facts only. No runtime type exposes `healthy=true`.
2. **Positive judgments expire.** Every `CURRENT` judgment depends on evidence
   with a finite receiver-owned expiry. At or after the earliest required
   support expiry, reevaluation cannot return `CURRENT` from that support. The
   judgment exposes that support deadline on the receiver clock.
3. **Missingness cannot preserve a positive.** Missing, expired, refused, or
   insufficiently replicated required coverage makes the named reliance
   conditions unsatisfied.
4. **Unknown is not weak health.** `UNKNOWN` makes no positive subject claim.
5. **Adverse findings are sticky by named law.** A negative or contradictory
   record remains visible until explicit resolution, explicit supersession, or
   expiry under a policy rule identified before the transition. The initial
   single-observer rules are `same_observer_newer_sequence/v1`,
   `observer_incarnation_replacement/v1`, and
   `receiver_freshness_expiry/v1`; supersession is a sparse event.
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
    comparable only inside the same identified receiver-clock generation. An
    evaluation-time regression within one generation is clamped to the last
    evaluation point, marks monitoring `BLIND`, and cannot restore reliance.
26. **Expiry is inclusive.** Evidence evaluated at `arrival + effective
    validity - receiver-verifiable pre-arrival delay` is expired, not current;
    the delay is zero when no qualified delay fact exists.

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
    consumer, reliance-policy generation, observation-policy generation,
    trigger class, and diagnostic profile before expiry produces no second
    execution request.
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

## Receiver, scheduler, and generation transitions

49. **No generation inheritance.** A prior `CURRENT` certificate is invalid
    after any relevant reliance-policy, consumer-profile,
    evaluator-semantic, observer-set, observation-policy, subject-incarnation,
    or context-activation transition.
50. **Content equality is not identity.** Equal policy bytes or semantic
    digests under different generations cannot preserve or recreate standing.
51. **Rollback and ABA do not resurrect.** Returning to an earlier body or
    identifier is a new activation and cannot reuse an earlier certificate,
    deadline, or evaluation result.
52. **Generation barriers precede reconsideration.** The affected consumer is
    first `UNKNOWN` under the new exact activation. Only a separate explicit
    evaluation may establish another category.
53. **Consumer transitions are isolated.** Changing Consumer A's context does
    not change Consumer B's context, schedule, or certificate.
54. **The scheduler owns positive expiry.** Every runtime-issued `CURRENT`
    certificate has exactly one scheduled inclusive reevaluation at its
    earliest required support deadline.
55. **No pulse is needed for withdrawal.** Reaching a scheduled support
    deadline reevaluates and withdraws stale positive standing even with an
    empty input stream.
56. **Simultaneous order is total.** Generation barriers precede matching
    inclusive expiry, which precedes pulse processing and explicit
    reevaluation at the same logical instant.
57. **Stale schedules are activation-bound.** A deadline scheduled by an old
    context cannot reevaluate or refresh a later context.
58. **Lateness is evidence about the monitor.** Scheduler overshoot is measured
    from the original deadline and never shifts freshness.
59. **Bounds fail visibly.** Queue, subject, consumer, observer, stream,
    incarnation, schedule, context-history, escalation, certificate, receipt,
    and sparse-history exhaustion produces typed refusal or blindness; none
    silently evicts evidence while preserving `CURRENT`.
60. **Restart has no current standing.** Historical transitions, receipts, and
    contradictions may reopen, but hot evidence, schedules, and `CURRENT`
    certificates do not. Restart begins `UNKNOWN`.
61. **Contradictions survive semantic transitions.** Policy/profile/evaluator/
    observer-set changes and diagnostic completion cannot clear an applicable
    active contradiction.
62. **Subject replacement is named, not deletion.** Only an explicit configured
    subject-incarnation replacement may mark an old-incarnation contradiction
    inapplicable under `subject_incarnation_replacement/v1`; its historical
    record remains.
63. **Certificates are bounded and exact.** A certificate names the complete
    activated reliance context, evidence refs, missing premises,
    contradictions, coverage, expiry, next evaluation, and no-mutation
    statement. Overflow withholds the positive certificate and emits an
    explicit refusal; it never truncates a claim.

## Local reactor and historical journal

64. **A live actor owns wakeup.** While the reactor reports operational
    temporal custody, its dedicated thread owns the earliest active support
    deadline and invokes deterministic evaluation without external
    `run_until` calls.
65. **Actual wake time governs late evaluation.** A late timer wake evaluates
    at actual receiver time. It never evaluates at the requested deadline or
    moves the encoded support expiry.
66. **Non-operational custody exposes no live standing.** Mailbox saturation,
    response timeout, condition-variable failure, actor unwind, required
    journal failure, command-channel abandonment, and termination clear the
    shared certificates, evidence count, and deadline surface.
67. **Timer and journal failures stay distinct.** Reactor wakeup/actor failure
    and journal append/sync/bound failure have different typed conditions and
    counters; neither is flattened into a reassuring scalar.
68. **Monotonic epochs never bridge restart.** Every persisted monotonic value
    names one process epoch. Values from different epochs are provenance and
    are never subtracted to reconstruct freshness or elapsed time.
69. **Restart empties temporal state.** After process restart, standing is
    `UNKNOWN`, supporting evidence is empty, and active deadlines are empty,
    regardless of recovered historical `CURRENT` records.
70. **Journal append is bounded and non-evicting.** Record-count, payload-size,
    and file-size exhaustion refuse before writing an extra record. No append
    silently removes an older record.
71. **Acknowledgement names an exact boundary.** An acknowledgement identifies
    the record sequence, frame digest, declared durability mode, completed
    data/commit sync phases, and returned-ack fact. No failed append returns a
    durable acknowledgement.
72. **Recovery stops at first damage.** Scanner recovery never searches beyond
    a damaged frame for later magic and never presents a damaged suffix as
    clean EOF.
73. **Incomplete prefix remains incomplete.** A permitted valid-prefix
    projection carries its damage class, first offset, incomplete-history
    status, and operator-action requirement.
74. **Refused recovery cannot project.** Interior corruption, sequence
    ambiguity, unsupported structure, and other `Refused` outcomes cannot be
    converted into runtime historical state.
75. **Checksums are not authority.** Frame and commit SHA-256 values detect
    accidental corruption; they authenticate neither writer nor storage.
76. **History restores no execution lease.** Historical escalation and
    deduplication events restore no active request owner, suppression lease,
    retry permission, or diagnostic authority.
77. **Contradiction custody is non-laundering.** A recovered contradiction may
    continue to block a later explicit evaluation; diagnostic acceptance,
    completion, append, or restart never resolves it.
78. **Journal records grant no mutation.** Every journal envelope and all
    reactor/recovery outputs structurally carry `mutation_authority: none` or
    contain no authority field at all.

## Qualified-generation binding

79. **Declaration is not qualification.** A generation label, digest, source
    identifier, or canonical manifest cannot independently satisfy the binding
    premise for `CURRENT`.
80. **Qualification is not activation.** A valid manifest, checked report, or
    accepted qualification certificate cannot construct the live activation
    capability or establish present reliance.
81. **Every positive role is exact.** The running executable, evaluator,
    reliance policy, consumer profile, observer set, observation policy,
    runtime configuration, and semantic contracts must all match the accepted
    manifest exactly. Any missing or mismatching required role withholds
    `CURRENT` and creates no support deadline.
82. **Active bindings are process-local capabilities.** The accepted binding
    owns a retained executable handle, is neither cloneable nor serializable,
    and names one fresh process/activation occurrence.
83. **Positive certificates name qualification.** Every `CURRENT` support
    certificate names the exact manifest, qualification certificate,
    activation receipt, process occurrence, and generation-set identity that
    supplied its live premise.
84. **Receipts remain history.** A prior activation receipt, including a
    synced `QualifiedAndMatched` receipt, cannot restore an accepted binding,
    evidence, standing, or a deadline after restart.
85. **Lifecycle changes are barriers.** An accepted local supersession or
    revocation fact withdraws positive standing and cancels its deadline. A
    successor does not inherit the predecessor's activation or evidence.
86. **Lifecycle authority is configured and local.** An arbitrary lifecycle
    assertion or mismatched authority identifier is refused; V1 claims no
    signer, organizational, or global revocation authority.
87. **Canonical bytes are singular.** Identity-bearing package objects reject
    duplicate or unknown fields, alternate field order or whitespace,
    unsupported digests, duplicate/missing roles, body/digest disagreement,
    and bytes beyond the bounded canonical object.
88. **Qualification claims are evidence-bounded.** A certificate may name
    only claims present in both its exact manifest declaration and its checked
    machine-readable qualification report.
89. **Binding failure classes stay distinct.** Artifact mismatch,
    qualification refusal, lifecycle refusal, timer failure, journal failure,
    and observation blindness are separate typed conditions; none is collapsed
    into a scalar status.
90. **Qualification grants no operational authority.** Manifests, reports,
    certificates, lifecycle facts, activation receipts, accepted bindings,
    and support certificates grant no continuation, diagnostic-execution,
    deployment, signing, revocation, or mutation authority.

## Receiver-boundary custody

91. **Authentication is not reliance.** A valid pinned-key signature, sender
    qualified-activation assertion, receiver admission, and consumer judgment
    remain four separate facts.
92. **Sessions bind both live occurrences.** A sender offer names the sender
    process; the receiver challenge binds that exact offer/occurrence; the
    sender binding answers it; and a receiver-signed acceptance is required
    before emission. The sender verifies an exact receiver-policy anchor and
    sender-package-bound composite identity; equal policy labels cannot
    substitute content. Historical handshake bytes cannot create live state.
93. **Arrival is receiver-owned.** Remote V1 support is anchored only at the
    receiver monotonic arrival. Sender time, retry, duplicate, replay and
    reorder never move that arrival or deadline.
94. **Authenticated refusal is not evidence.** Signature success with a key,
    package, process, observer, subject, incarnation, scope, sequence, payload
    or lifecycle mismatch creates a bounded receipt and no verified token.
95. **Remote support names exact custody.** A support certificate using remote
    evidence names the exact sender, receiver, packages, activations,
    occurrences, session, envelope, payload, admission receipt and arrival.
96. **Replay custody is bounded.** One fixed bitmap/high-water state refuses
    duplicate, replay, reorder and over-window inputs without retaining an
    unbounded historical identity set or renewing freshness.
97. **Occurrence conflict fails closed.** Two overlapping sender occurrences
    claiming one observer/key/scope withdraw affected standing; last arrival
    never selects a winner.
98. **Transport loss is not subject contradiction.** Silence, partition,
    overload and authentication refusal may remove reliance but do not invent
    a contradictory subject observation.
99. **Receiver-boundary restart is empty.** Either-peer restart destroys live
    offers, challenges, sessions, accepted remote activation, evidence and
    deadlines. Historical receipts cannot reconstruct them.
100. **Custody grants no authority.** Keys, policies, offers, challenges,
    bindings, receiver acceptances, envelopes, admission receipts and support
    references grant no continuation, transport-administration, diagnostic,
    deployment, signing, revocation or mutation authority.

## Maximum stale-positive duration

The deterministic kernel recomputes freshness on every ingest and explicit
tick. The local reactor additionally owns a real monotonic wakeup for the
earliest active deadline. For an operational reactor, the observed local
duration is:

```text
stale-positive overshoot = actual withdrawal - encoded support expiry
```

The experiment records the observed duration between the earliest required
support expiry and the first non-positive evaluation. This observed value is
`maximum_stale_positive_duration_ms`. It is an experimental measurement, not a
hard real-time guarantee or a bound under arbitrary host load. A caller using
the deterministic kernel without the reactor still makes no between-call
latency claim. Once the reactor ceases to report operational custody, its
shared surface exposes no live certificate rather than pretending a timer
bound remains enforced.
