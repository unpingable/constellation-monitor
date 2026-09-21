# Bounded receiver and scheduler contract

Status: normative for the deterministic receiver/scheduler semantic kernel.
The local actor, monotonic-epoch, append, sync, and corruption-recovery rules
are additionally governed by [crash-fault-contract.md](crash-fault-contract.md).
Artifact qualification and process-local activation are governed by
[qualified-generation-contract.md](qualified-generation-contract.md).
Authenticated remote admission is additionally governed by
[receiver-boundary-contract.md](receiver-boundary-contract.md).
The runtime and all record names remain provisional.

## Owned question

The receiver/scheduler owns this bounded question:

> At receiver evaluation time, under this exact activated reliance context,
> does current admitted evidence support this consumer's named reliance
> premises, and when must that answer next be withdrawn or reevaluated?

It does not own subject health, observer truth, diagnostic authority,
remediation, distributed scheduling, durable current standing, or hard
real-time execution.

## Exact reliance context

A support certificate binds all of:

- reliance-policy generation and policy semantic digest;
- consumer-profile generation;
- evaluator-semantic generation;
- observer-set/coverage-profile generation;
- observation-policy generation;
- one unique context-activation occurrence;
- subject identity and subject incarnation; and
- receiver clock generation and evaluation time;
- exact qualified manifest and qualification-certificate digests; and
- one fresh process-local activation-receipt/process occurrence; and
- when enabled, one exact load-bearing sender/receiver transport-policy role,
  generation and canonical policy digest.

Generation identity and semantic content are different facts. Equal policy
digests under different generations are not equal contexts. Reusing an earlier
body, rolling back configuration, or returning to earlier identifiers is an
activation transition and cannot recover an earlier certificate. A context
activation identity is single-use within the bounded runtime history.

`PulseFrameV1.observation_policy_generation` identifies the collection law
under which an observation occurrence was produced. It does not identify the
consumer reliance law. `ReliancePolicyV1.generation` identifies that reliance
law and separately declares which observation-policy generation it admits.
It is an index, not authority: no caller-supplied generation field can satisfy
the qualified-binding premise on its own.

## Generation barrier

Any change to a reliance-policy generation, consumer-profile generation,
evaluator-semantic generation, observer-set generation, admitted observation
policy, configured subject incarnation, exact artifact identity, accepted
qualification package, or qualification lifecycle state installs a generation
barrier for the affected consumer. The barrier:

1. cancels that consumer's old scheduled support certificate;
2. emits `UNKNOWN` under the new exact context with
   `generation_transition_requires_reevaluation` (or the corresponding
   subject-incarnation reason);
3. preserves historical evidence and applicable contradiction custody;
4. emits no diagnostic solely because configuration changed; and
5. permits `CURRENT` only after a later explicit evaluation creates a new
   certificate naming the new context and live `QualifiedAndMatched` binding,
   with all evidence premises actually present.

The barrier is required even when the policy body digest is equal, the change
loosens requirements, or the new body is a rollback. No code path converts the
old certificate into a new one.

## Deterministic event order

Inputs carry receiver-monotonic logical time and a runtime-assigned ingress
ordinal. Within one clock generation, time cannot regress. At one logical
instant the runtime processes this total order:

1. clock-integrity loss and latched capacity/overload withdrawal;
2. subject-incarnation and reliance-context activation barriers, ordered by
   subject and stable replacement/consumer/activation identities;
3. inclusive support-expiry deadlines, ordered by deadline, subject, consumer,
   and the activation that scheduled them;
4. admitted pulses, ordered by subject, observer, observer incarnation,
   sequence, and observation digest;
5. diagnostic dispositions and receipts, ordered by request and receipt
   identity; and
6. monitor restoration and explicit reevaluation, ordered by subject,
   consumer, and stable input identity.

The receiver ingress ordinal is only the final tie-breaker for exact duplicate
semantic keys. Distinct same-instant events therefore do not acquire meaning
from a thread or channel race.

A stale scheduled item names its activation and cannot affect a later one. If
expiry and a policy transition share an instant, the barrier withdraws the old
standing first; the old deadline is then a superseded schedule item. Any new
evaluation is a separate step under the new context. Thread scheduling,
unordered maps, sender wall clocks, and ambient wall time do not select order.

A remote envelope does not enter this ordering directly. The receiver-boundary
gate first assigns receiver-owned arrival and produces a move-only verified
observation token. That token becomes an admitted pulse at its already fixed
arrival instant; authentication, replay or identity refusal produces no
evaluator input and cannot renew freshness.

## Receiver-owned time and deadlines

The receiver assigns arrival time from its identified monotonic clock. Sender
wall time does not establish freshness. The evaluator exposes the earliest
inclusive expiry among support required for a `CURRENT` result. The runtime
schedules exactly that deadline and reevaluates without requiring another
pulse.

At `now >= deadline`, the old support is expired. Scheduler lateness is
recorded as `actual_reevaluation - expected_deadline`; it cannot move the
deadline or make expired evidence current. A receiver-clock regression marks
the runtime blind, clamps evaluation to the last comparable instant, withdraws
positive standing, and requires an explicit new clock generation/restart to
recover.

This is a best-effort local scheduler contract. The measured stale-positive
overshoot is not a hard real-time guarantee.

## Hard bounds and refusal posture

One `RuntimeBoundsV1` fixes nonzero maxima for:

- admitted subjects;
- consumers per subject;
- stable observers per subject;
- receiver stream identities, observer-incarnation history, and
  subject-incarnation history;
- pending inputs;
- scheduled deadlines;
- remembered context activations per consumer;
- active escalation requests;
- supporting references in one certificate; and
- retained sparse historical records and diagnostic receipts.

The optional remote canary adds one peer, one live session, one pending
offer/challenge, fixed sender and receiver datagram queues, a fixed replay
window, bounded gap state, accepted-message/rate counters, and bounded
acceptance receipts. Those live bounds refuse without eviction. Saturation
invalidates the affected session and withdraws the live positive surface.

No collection grows beyond its configured maximum. New subjects or consumers
are refused without eviction. New observer, stream, incarnation, or queue
identity at a full bound is refused and latches explicit blindness for the
affected subject (or runtime), synchronously withdrawing `CURRENT`. Deadline
capacity failure prevents issuance of the positive certificate it cannot
maintain. Historical-capacity exhaustion fail-stops further admission; it does
not overwrite older custody. Every case returns a typed refusal and increments
the matching metric.

No bound uses least-recently-used or arbitrary eviction. A later campaign may
define an eviction law, but this one chooses refusal because evidence loss must
not be invisible.

## Queue and overload contract

The pending queue is bounded before allocation. Duplicate, replayed, and
reordered pulse bytes still consume a bounded ingress occurrence but never
refresh admitted evidence. Queue saturation refuses the new item, records the
loss outside the saturated queue, marks monitor capability `BLIND`, and makes
the cached positive certificate unavailable immediately. Processing later
queued data cannot restore `CURRENT` while blindness remains latched.

Recovery from overload is an explicit monitor-capability transition that emits
an `UNKNOWN` restoration barrier, followed by a separate explicit
reevaluation; it is not inferred from an empty queue and restoration itself
cannot reissue `CURRENT`.

## Support certificate

`RelianceSupportCertificateV1` is bounded and identifies:

- consumer and exact subject scope/incarnation;
- the complete activated reliance context and policy body digest;
- receiver evaluation time and clock generation;
- categorical judgment and evidence-window identity;
- sorted supporting evidence references;
- sorted missing premises;
- sorted applicable contradiction identities;
- achieved and required coverage;
- earliest support expiry and next scheduled reevaluation;
- escalation state/disposition; and
- the exact accepted manifest, qualification certificate, activation receipt,
  process occurrence, and generation-set identity when the judgment is
  `CURRENT`; and
- for each remote observation actually supporting the result, a bounded exact
  custody reference naming receiver process/epoch/policy/activation, sender
  key/process/manifest/certificate/activation assertion, exact receiver-policy
  anchor and sender-package-bound composite identity, offer/challenge/
  binding/envelope, observer/subject/incarnation/sequences/payload, receiver
  arrival, admission receipt and accepted evidence identity; and
- structural `mutation_authority: none`.

A `CURRENT` certificate is valid only before its earliest support expiry and
only while its exact context activation and non-serializable qualified-artifact
activation remain active. A non-current certificate has no positive support
deadline. Certificate size overflow cannot truncate a claim; it makes reliance
`UNKNOWN` with an explicit bound reason. A label, digest, canonical manifest,
certificate, source commit, passing-test record, or prior activation receipt
without the live accepted activation is an explicit missing premise.

## Persistence and restart

`RuntimeHistoricalStateV1` is a history-only persistence payload. It may
contain bounded sparse events (including a certificate that was `CURRENT` at
an earlier occurrence), contradiction custody, and correlated diagnostic
receipts. It contains no authoritative current projection, hot pulse window,
scheduled deadline, receiver lineage, or active escalation lease. The
deterministic kernel qualifies exact serialization/recovery semantics. The
enclosing local journal now qualifies bounded framing, append acknowledgement,
`sync_data`/`sync_all` boundaries, first-damage scanning, and process-kill
recovery under the separate crash-fault contract. Neither layer makes current
standing crash durable.

Historical sender offers, receiver challenges, sender bindings, receiver
session acceptances, envelopes, acceptance receipts and remote custody
references remain history only. The live session, accepted remote activation,
replay window and `VerifiedRemoteObservationV1` token are not serializable and
cannot be reconstructed by journal replay.

On restart the runtime uses a new receiver incarnation and clock generation,
loads historical records as history, restores applicable unresolved
contradiction custody, discards every accepted artifact activation, and
installs a restart barrier. Every current standing is `UNKNOWN` until a new
process locally remeasures and accepts the exact package and then performs an
explicit current evaluation under a newly activated exact context.
Deserializing a historical `CURRENT` transition or activation receipt never
recreates standing.

`JournalHistoryProjectionV1` may project a clean journal or a specifically
permitted valid prefix. It carries recovery outcome, damage, completeness, and
operator-action status so an incomplete prefix is not presented as healthy
history. A `Refused` scan cannot project history. No journal timestamp from a
prior `MonotonicEpochV1` is compared with the restart clock.

Thus these remain separate:

```text
historical evidence exists
!= current reliance is established
```

## Contradiction custody

The campaign distinguishes:

- the immutable historical contradiction record;
- its grounding subject incarnation;
- the consumer evaluator for which it is applicable;
- whether it currently blocks that consumer;
- its existing explicit resolved/superseded/expired lifecycle status; and
- inapplicability caused by an explicit configured subject replacement under
  `subject_incarnation_replacement/v1`.

Policy, profile, evaluator, or observer-set transitions do not clear active
contradictions. They remain blocking through the generation barrier and any
later reevaluation. Diagnostic request acceptance and diagnostic completion
have no contradiction-lifecycle effect. A configured subject replacement may
make an old-incarnation contradiction inapplicable to the replacement while
preserving it in history and emitting the named custody transition.

This is not a general contradiction-resolution language. Policy-based
supersession beyond the existing lifecycle remains a documented seam.

## Escalation behavior

Only an evidence evaluation transition away from a supported `CURRENT` result
may cross the existing configured threshold. A pure generation barrier does
not invent a diagnostic need. Equivalent active requests remain deduplicated;
reevaluation and scheduler lateness do not slide expiry. Runtime request and
history bounds can refuse further escalation but cannot broaden it. No request,
disposition, receipt, certificate, or runtime event grants mutation authority.
