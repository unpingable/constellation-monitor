# Runtime architecture

Status: normative for the qualified vertical slice, bounded receiver/scheduler,
local crash-fault custody, qualified generation, and bounded receiver-boundary
campaigns. Public product identity is `constellation-monitor`; Pulse is hosted
inside this repository. Existing internal crate and protocol names remain
stable compatibility identities.

## Product boundary

The runtime is a consumer-indexed present-confidence evaluator, not a health
oracle. It receives bounded observation occurrences, adds receiver-owned facts,
maintains a small ephemeral evidence window, and derives a categorical judgment
with exact reasons. When a configured reliance bound ceases to hold, it may
emit one deduplicated request for a predeclared deeper diagnostic.

```text
observer                         monitor plane
--------                         -------------
bounded acquisition
  -> PulseFrameV1 ==compact==> receiver annotation
                                -> admission / continuity tracking
                                -> ephemeral evidence window
                                -> consumer policy evaluation
                                -> PresentStateJudgmentV1
                                -> sparse transition event
                                -> optional DiagnosticEscalationRequestV1
                                             |
                                             v
                                  closed local L3 bridge stub
                                  -> disposition + mock receipt
```

The receiver/scheduler campaign adds one enclosing owner without changing the
semantic jurisdiction:

```text
bounded ingress -> receiver annotation -> pending input order
                                      -> exact generation barrier
                                      -> per-consumer evaluator
                                      -> support certificate
                                      -> earliest-deadline scheduler
                                      -> sparse history sink
```

`pulse-runtime` is a local single-process coordinator, not a distributed
scheduler. Its full bound, ordering, restart, and generation contract is
normative in [runtime-contract.md](runtime-contract.md).

The crash-fault campaign adds a narrow operational owner without changing the
deterministic kernel or evidence semantics:

```text
bounded caller commands
        |
        v
bounded mailbox --notify--> dedicated reactor thread
                             | process-local Instant / exact epoch
                             | earliest support deadline
                             v
                    ReceiverSchedulerRuntime::run_until(actual_now)
                             |
                  +----------+-----------+
                  |                      |
          ephemeral live surface     append-only historical journal
          certificates/evidence      sparse events/contradictions/receipts
          support/deadlines           checksummed frames + commit markers
                  |                      |
             process death          scan first damage; report health
                  |                      |
                  +----------+-----------+
                             v
                    restart UNKNOWN, support=0,
                    deadlines=0, new monotonic epoch
```

The reactor is one dedicated standard-library thread with a mutex, condition
variable, and fixed mailbox capacity. It is not an async runtime. The journal
is one bounded regular file with no database, compaction, rotation,
replication, or query layer. Their exact contract is normative in
[crash-fault-contract.md](crash-fault-contract.md).

The qualified-generation campaign adds a fail-closed premise before positive
reliance without changing evaluator category precedence or timer custody:

```text
declared generation set
        +
canonical artifact manifest --exact--> checked qualification report
        +                                      |
local acceptance/lifecycle policy             v
        +                              qualification certificate
opened /proc/self/exe handle                   |
        +                                      v
canonical owned runtime values ------> fresh process-local activation receipt
                                               |
                                  non-serializable accepted activation
                                               |
                                               v
                              CURRENT support certificate may name
                              exact manifest/certificate/receipt/context
```

The three judgments remain separate: a generation can be declared without a
package, a package can be qualified without being active, and a historical
activation receipt cannot reconstruct the live accepted activation. Every
nonmatching or ambiguous binding state prevents `CURRENT` and cancels the
affected consumer's inherited support deadline. Binding failure, timer
failure, journal failure, and observation blindness remain distinct classes.
The complete contract is
[qualified-generation-contract.md](qualified-generation-contract.md).

The receiver-boundary campaign adds one narrow authenticated custody path. It
does not make transport authentication equivalent to sender qualification,
receiver admission, or consumer reliance:

```text
sender live activation                        receiver live activation
        |                                             |
 signed offer (sender occurrence/package)             |
        +---------------- UDP ------------------------>|
        |<--------------- signed challenge -----------+
 signed binding (qualified local assertion)            |
        +--------------------------------------------->|
        |<--------- signed receiver acceptance --------+
 signed exact observation envelope                     |
        +--------------------------------------------->|
                                                      v
                                           receiver-owned arrival
                                           bounded admission receipt
                                           move-only evidence token
                                           consumer A: CURRENT
                                           consumer B: UNKNOWN
```

Every datagram is at most 1,232 bytes and uses one canonical PCN1 binary body
plus a domain-separated Ed25519 signature under exact locally pinned public
keys. The sender offer and receiver acceptance are load-bearing: an old
challenge cannot bind a restarted sender, and a provisional sender binding
cannot emit until the live receiver occurrence acknowledges it. Neither
signature nor exact package assertion is remote attestation.

The sender also pins a canonical receiver-policy anchor rather than trusting
its generation label. The receiver challenge binds that anchor to the exact
sender manifest/certificate admitted by the receiver; the sender recomputes
the composite policy identity. This breaks the qualification-package hash
cycle without permitting same-label policy substitution.

The receiver alone assigns arrival, admits evidence, interprets coverage and
schedules expiry. Remote V1 evidence is explicitly `ArrivalAnchored`; sender
times are provenance and never extend freshness. Session/replay/queue state
and the verified evidence token are live and non-serializable. Restart on
either peer destroys them. Exact admission receipts and custody references may
be journaled as history but cannot reconstruct a session, evidence, deadline
or `CURRENT`. See
[receiver-boundary-contract.md](receiver-boundary-contract.md).

Transport, runtime interpretation, sparse event custody, and presentation are
separate. A transport adapter cannot assign a judgment, and a renderer cannot
change one.

## Terms

### Subject

The entity or exact scope about which observations are made. It has a stable
identity and a subject-incarnation identity. A subject restart creates a new
incarnation; evidence from the old incarnation cannot silently describe the
new one.

### Observer

The producer occurrence that acquired and emitted an observation. An observer
has a stable identity and a fresh incarnation identity for each process
lifespan. Observer identity is provenance, not proof of honesty or
independence.

### Observation profile

A versioned semantic identity defining the bounded signal vocabulary, coverage
tags, units, and collection limits for a pulse. It is not an NQ diagnostic
profile, a dynamic plugin, a rule engine, or authority.

### Pulse

One compact, bounded `PulseFrameV1`. It carries observer-local monotonic time,
but no sender time is trusted as the primary freshness source. Receipt proves
only an observation occurrence and its declared contents.

### Incarnation

A process- or subject-lifespan identity. Sequence continuity is meaningful only
within one observer incarnation. A newer incarnation supersedes prior
incarnations for current evidence but does not erase their historical events or
contradictions.

### Sequence continuity

The receiver-observed relation between monotonic sequence numbers for one
`(subject, observer, observer incarnation, profile, policy generation)` stream.
It distinguishes first, continuous, gapped, duplicate, replayed/out-of-order,
and restarted streams. It is evidence about delivery continuity, not subject
health.

### Receiver-observed arrival time

A monotonic time assigned by the receiver under an identified receiver clock
generation. It is the primary basis for local freshness. Receiver wall-clock
labels may be recorded for display but do not extend validity.

### Validity or freshness bound

The maximum interval for which an admitted pulse may support a positive
present-state judgment. Effective validity is the lesser of the pulse's
declared validity and the consumer policy maximum. With no receiver-verifiable
pre-arrival delay, a pulse expires at:

```text
receiver_arrival + effective_validity
```

When the receiver can establish a pre-arrival transport delay, that delay is
subtracted from effective validity. If it consumes the whole consumer-validity
budget, the occurrence is stale for that consumer even if the sender declared
a longer validity. Evaluation at or after expiry treats the pulse as expired.
Queueing, retry, or re-delivery never resets the original admitted arrival
time.

### Coverage

The policy-owned inventory of required observation tags and the active evidence
count for each tag. Pulse-declared coverage may narrow what that pulse supports;
it cannot shrink policy requirements. Aggregates retain expected, active,
missing, and expired tags plus per-observer contribution.

### Missingness

An explicit absence of the current evidence count required by policy. Missing
is not a negative subject observation and not a weak positive. It ordinarily
produces `UNKNOWN` unless a stronger retained contradiction or violation
applies.

### Contradiction

Two or more independently admitted evidence items with incompatible subject
incarnation, signal assessment, or profile-defined value relation. A
`ContradictionRecordV1` names its grounding evidence. It persists until an
explicit resolution, supersession, or expiry under a named policy rule.
Majority agreement is not a resolution rule.

### Observer disagreement

The current distribution of observer testimony, including compatible,
incompatible, and insufficient-to-compare states. Disagreement can ground a
contradiction; it is kept as a distinct confidence dimension so a resolved
record does not rewrite what observers actually reported.

### Confidence dimensions

The non-scalar evaluation axes:

- freshness;
- sequence continuity;
- observer availability;
- cross-observer coherence;
- coverage;
- provenance/authentication;
- transport degradation; and
- subject signal consistency.

No weighted sum or hidden score may replace them.

### Present-state judgment

A versioned evaluation record indexed by subject scope, consumer/reliance
class, observation-policy generation, aggregate coverage, evaluation time, and
evidence-window identity. It contains one category, every confidence
dimension, exact reasons, and explicit nonclaims. A `CURRENT` record also
exposes the receiver-clock deadline at which its present support set can no
longer sustain a positive result without replacement evidence; non-positive
records carry no such deadline.

### Escalation threshold

A consumer policy rule stating which transition away from `CURRENT` requests a
named deeper diagnostic. It is a request trigger, not an authorization rule.

### Diagnostic escalation request

A bounded, expiring request for one predeclared diagnostic profile, correlated
to the evidence window and causal judgment transition. It contains no command
or mutation authority.

### Supersession

An explicit statement that a newer identity or named rule replaces an older
record for a particular use. Supersession preserves the older record and its
reason; it is not deletion or retroactive correction.

### Resolution

An explicit disposition of a contradiction with a resolver identity, time,
named rule, and explanation. Resolution stops that record from blocking future
judgments only according to the named rule. New current evidence is still
required for `CURRENT`.

### Named negative-finding lifecycle rules

The initial slice admits only two automatic applicability-ending rules for a
single-observer negative signal occurrence:

- `same_observer_newer_sequence/v1` (or the explicit
  `observer_incarnation_replacement/v1` case) records a sparse supersession
  event binding the prior and replacement evidence references; and
- `receiver_freshness_expiry/v1` ends current applicability at the
  receiver-owned inclusive expiry and preserves the earlier `SUSPECT`
  transition as history.

Neither rule resolves an independently grounded contradiction. Contradictions
continue to require their separate lifecycle act.

## Identities and generations

These identities are deliberately not interchangeable:

| identity | minted when | meaning |
|---|---|---|
| subject | configuration admits a scope | stable logical observation target |
| subject incarnation | subject lifecycle begins | one concrete lifecycle of the target |
| observer | configuration admits a producer | stable producer role |
| observer incarnation | producer process starts | one sequence-number namespace |
| observation profile | profile semantics are defined | exact pulse field/coverage meaning |
| observation-policy generation | collection law changes | exact pulse acquisition semantics admitted by a reliance policy |
| reliance-policy generation | consumer evaluation law changes or is reissued | exact consumer evaluation law; content equality is insufficient |
| consumer-profile generation | consumer premise/profile definition changes | exact reliance class semantics |
| evaluator-semantic generation | evaluator interpretation changes | exact runtime derivation semantics |
| observer-set generation | required observer/failure-domain configuration changes | exact coverage population law |
| context activation | any relevant context is activated | single-use occurrence preventing rollback or ABA inheritance |
| evidence window | evaluator selects current inputs | exact bounded evaluation basis |
| transition | semantically relevant judgment changes | causal before/after occurrence |
| escalation request | threshold crossing is admitted | one bounded diagnostic request |
| diagnostic run | bridge accepts a request | one bounded execution occurrence |
| artifact manifest | one exact artifact/generation inventory is canonicalized | content identity and assumptions, not qualification |
| qualification certificate | checked results are bound to one exact manifest | local exact qualification evidence, not activation or signer authority |
| activation occurrence | one process freshly measures and accepts one package | non-serializable local premise for positive reliance |

A change in semantic policy creates a new reliance-policy generation. A new
generation is also required when an equal or rolled-back body is activated as
a new law. Old evidence may remain inspectable, but it can be reconsidered
only by an explicit evaluation whose support certificate names the new exact
activation and whose policy explicitly admits the observation profile and
observation-policy generation. No prior standing is copied.

Generation labels are still useful indexes, but they are no longer sufficient
premises. The active support context also identifies the exact qualified
manifest, qualification certificate, activation receipt, process occurrence,
and generation-set digest. Exact content under another generation still needs
a new package and activation; equal labels with different bytes fail role by
role.

## Receiver admission

The receiver validates the closed schema and bounds before evaluation. It then
annotates the frame with receiver identity/incarnation, receiver monotonic
arrival, sequence gap, duplicate/replay classification, transport path, and
authentication result.

For the bounded remote canary, admission has an earlier gate: canonical UDP
framing, exact live offer/challenge/binding/receiver-acceptance session,
pinned sender signature, exact sender package/activation assertion, observer,
failure-domain claim, subject/incarnation, sequence/replay and payload all must
match the receiver's own qualified acceptance policy. Only the resulting
move-only `VerifiedRemoteObservationV1` can enter the ordinary evaluator. An
authenticated refusal remains history and supplies no evidence.

For a known stream:

- the same sequence is a duplicate and cannot refresh evidence;
- a lower sequence is a replay/out-of-order occurrence and cannot replace a
  newer accepted frame;
- a jump records the exact sequence gap even if the new frame is usable;
- a new observer incarnation starts a new continuity lineage and marks
  continuity `RESTARTED`; and
- a frame from an older incarnation cannot become current after a newer
  incarnation has been admitted.

Receiver arrival cannot reveal every pre-receipt network delay. A first-seen
packet delayed entirely before the receiver, with no comparable clock or
transport proof, can be indistinguishable from a prompt packet. This is a
known nonclaim, not something sender wall time is allowed to conceal.

## Evidence window and evaluation

The evaluator holds only the latest admitted evidence required for the current
bounded window, retained contradiction records, active escalation deduplication
entries, recent diagnostic receipt correlations, and metrics. It is
deterministic over `(prior state, input record, evaluation time, policy)`.

For each policy-required coverage tag, active coverage is the count of fresh,
admitted, policy-compatible observer contributions. The required count is
consumer policy. Expired contributions are reported separately. A union that
contains every tag but lacks the required observer count is incomplete.

Category precedence preserves adverse evidence:

1. `CONTRADICTED` when an unresolved applicable contradiction exists.
2. `SUSPECT` when current admitted evidence grounds a declared bound violation.
3. `UNKNOWN` when freshness, observer count, coverage, provenance, or monitor
   blindness prevents the named reliance judgment.
4. `DEGRADED` when current evidence exists but a non-fatal continuity or
   transport degradation means the exact `CURRENT` contract is not met.
5. `CURRENT` only when every named positive reliance condition is presently
   satisfied.

The precedence selects a headline; it never removes lower-dimensional facts.
For example, a retained contradiction can remain the headline while transport
is simultaneously blind.

The exact required explanation for an incomplete but otherwise non-violating
window is:

```text
No violating observation is currently known, but coverage is incomplete and reliance is therefore UNKNOWN.
```

## Categorical semantics

| category | exact claim | important nonclaim |
|---|---|---|
| `CURRENT` | This consumer's named reliance conditions are satisfied at this evaluation time by this evidence window. | The subject is healthy, truthful, globally known, or safe to mutate. |
| `DEGRADED` | Current evidence exists, and a named observation-quality dimension is degraded. | Reliance remains granted merely because some evidence is fresh. |
| `SUSPECT` | Current admitted evidence contains a named subject-bound violation. | The observation is necessarily truthful or causal. |
| `UNKNOWN` | Available evidence cannot support the named reliance judgment. | Healthy, failed, or approximately current. |
| `CONTRADICTED` | Incompatible grounded evidence remains applicable and unresolved. | The majority is correct or the minority can be discarded. |

`ESCALATED` is not a category. `not_requested`, `requested`, `accepted`,
`refused`, `narrowed`, `deferred`, and `completed` are escalation lifecycle
states recorded beside the unchanged evidence judgment.

## Consumer-indexed outcomes

Policies name their required coverage, observer count, authentication posture,
maximum validity, tolerated transport state, signal relations, and escalation
profile. Thus the same pulse window may produce:

```text
CURRENT for capacity-display/v1
UNKNOWN for destructive-automation-preflight/v3
```

Neither judgment authorizes mutation. The second policy may demand two
authenticated independent observers while the first requires one identified
local observer. The explanation must make that difference visible.

## Contradiction lifecycle

Coherent later pulses do not silently delete a contradiction. A record becomes
non-blocking only through:

- explicit resolution under a named rule;
- explicit supersession by a named, identity-bound record; or
- expiry under a named contradiction-expiry rule that the policy already
  contains.

The evaluator kernel retains the existing explicit-resolution operation; the
new receiver/scheduler does not expose a broader resolution command or policy
language. It does not enable implicit quorum resolution. Resolution is a
sparse durable event and does not itself supply current coverage.

## Diagnostic receipt handling

A successful diagnostic receipt is correlated to its request and evidence
window and retained as bounded auxiliary evidence. It can explain what deeper
observation occurred. It does not automatically resolve a contradiction,
replace pulse coverage, reset a pulse's arrival time, or produce `CURRENT`.
After its own named applicability expires, it remains history only.

## Persistence split

The vertical slice keeps pulse state in memory. It emits JSONL-compatible
`SparseDurableEventV1` records only for:

- semantic judgment transitions;
- contradiction creation/resolution/supersession;
- named supersession of adverse single-observer observations;
- escalation request/disposition/deduplication;
- diagnostic receipt correlation; and
- monitor-plane degradation/recovery.

The receiver runtime additionally emits sparse context activations, bounded
support-certificate occurrences, deadline reevaluations, runtime refusals,
contradiction-applicability changes, and restart facts.

It does not implement distributed storage or long-term pulse retention.

The receiver runtime may reopen an exactly serialized bounded history payload,
contradiction custody, and receipts. A historical event may say that a
certificate was `CURRENT` then; it is not an authoritative current projection.
The runtime deliberately cannot reopen hot evidence, schedules, active
escalation ownership, or positive standing. Restart installs `UNKNOWN` before
any explicit current evaluation.

The local journal qualifies an append protocol for these history-only records.
Each data frame binds a closed record kind, exact payload length, sequence,
process monotonic epoch, prior-frame checksum, and payload checksum. A separate
checksummed commit marker distinguishes a committed record from an incomplete
suffix. `FileSynced` acknowledgement is returned only after `sync_all` has
returned for both the data frame and its commit marker. Creation separately
syncs the empty file and parent directory entry. This is an operating-system
durability boundary, not a physical-media, kernel, filesystem, or host-crash
guarantee.

Recovery never scans past the first defect. A torn suffix after a committed
prefix may be projected only with explicit incomplete-history and
operator-action fields. Interior corruption and other `Refused` outcomes
cannot be projected into runtime history. A self-contained file cannot detect
that a previously longer history was truncated at an exact committed-record
boundary without an external trusted tail anchor; this limitation cannot
restore current standing and remains a named gap.

## Experimental metrics

The evaluator exposes:

- pulse-to-evaluation latency;
- maximum observed stale-positive duration;
- failure-to-`UNKNOWN` latency;
- failure-to-`CONTRADICTED` latency;
- failure-to-escalation latency;
- false escalation count in declared normal traces;
- active and expired coverage;
- dropped stale pulse count;
- duplicate count;
- sequence gap count; and
- escalation deduplication count.

Failure-to-transition metrics require an externally supplied fault marker in a
replay or controlled experiment; otherwise they remain `not measured` rather
than inventing a failure start time. No metric is a hard real-time guarantee.
The evaluator tick interval plus effective validity bounds how long a cached
positive judgment can outlive its evidence; observed overshoot is recorded as
maximum stale-positive duration.

The enclosing runtime separately exposes expected support expiry, actual
reevaluation, scheduler lateness, policy-transition withdrawal latency,
capacity refusals, escalation deduplication, and recovered-history counts.

The local reactor adds wakeup count, actual wakeup lateness, autonomous
deadline-withdrawal count, mailbox refusal, wakeup/actor/journal failure class,
and maximum journal append/sync latency. Journal recovery separately exposes
outcome, damage class, first damaged offset, valid-prefix bytes, records
recovered, completeness, and operator-action requirement. Timer custody and
journal custody are not collapsed into one scalar status.
