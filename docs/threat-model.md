# Threat model

Status: normative claim boundary for the experimental vertical slice, local
crash-fault custody, and qualified-generation binding campaigns. This is not a
production security assessment.

## Assets

The runtime protects the integrity of:

- subject, observer, incarnation, profile, and policy identities;
- receiver-observed arrival and sequence facts;
- current coverage and missingness;
- unresolved contradiction records;
- consumer-indexed judgment explanations;
- escalation scope, bounds, expiry, and deduplication;
- diagnostic receipt correlation; and
- process-local monotonic epoch separation;
- explicit reactor temporal-custody state;
- journal sequence, frame integrity, valid-prefix completeness, and
  acknowledgement boundary; and
- canonical artifact-package identity and process-local activation identity;
- separation of declaration, checked qualification, and live activation; and
- the fact that no monitor-plane object grants mutation authority.

Availability matters because observation blindness is itself a semantic fact.
Confidentiality is limited to avoiding collection of unnecessary data; the
initial signals and fixtures are not a secret-storage design.

## Trust assumptions

The initial slice assumes:

- evaluator code and configured policy bytes are locally trusted;
- receiver monotonic time progresses within one identified clock generation;
- process memory is not being arbitrarily rewritten by an attacker;
- configured observer and subject identities are operator-provided bindings;
- the local bridge registry and harmless stub implementation are trusted to
  match their compiled declaration; and
- supplied replay files are untrusted input but the replay harness itself is
  trusted;
- the local OS implements `Instant`, condition variables, file append,
  `sync_data`, and `sync_all` according to their documented interfaces; and
- journal checksums detect accidental corruption only. Journal storage and the
  writer host are not treated as adversarially authenticated;
- SHA-256 content identities rely on collision resistance and are neither
  authenticity nor authorization evidence; and
- Linux `/proc/self/exe`, ordinary inode/timestamp behavior, the kernel,
  loader, compiler, and process memory behave consistently with the narrow
  local measurement contract. None is independently attested.

An authentication result is an input dimension, not proof of observation
truth. V1 includes a placeholder/authentication carrier but does not build a
key, enrollment, rotation, or attestation infrastructure.

## Fault and adversary classes

### Lying or failing observer

An observer may self-report a reassuring value while its subject is failing,
omit a field, freeze, restart, or fabricate coverage. The evaluator preserves
provenance, disagreement, and missingness, but cannot prove truth from the
pulse alone. Independent observation and deeper diagnostics may reduce this
risk; V1 does not prove independence.

### Replay, duplication, and reordering

An input path may repeat or reorder valid frames. Per-incarnation sequences and
receiver annotations prevent a known old frame from replacing a newer frame or
refreshing its expiry. Exact gaps and duplicate counts remain visible.

### Delay

A queued frame may arrive after its usefulness. If the receiver already knows
a newer sequence, or the transport supplies a receiver-verifiable delay bound,
the delayed frame is dropped as stale/replay. A first-seen frame delayed wholly
before receiver arrival can be indistinguishable from prompt delivery when no
clock relationship or challenge exists. V1 does not claim to solve that
one-way-delay problem; consumers needing it must require a separately
qualified transport/profile.

### Incarnation confusion

An observer may restart and reset its sequence, or an old process may resume
after a new incarnation appears. Continuity keys include incarnation, and a
newer admitted incarnation prevents the old lineage from becoming current.
The monitor cannot verify that an observer honestly minted a new incarnation
without future authenticated enrollment.

Subject restart is separate. Old subject-incarnation evidence cannot describe
a new subject incarnation, and disagreement about subject incarnation is
contradictory evidence.

### Clock discontinuity

Sender wall clocks can jump and are never the primary freshness source.
Receiver monotonic reset requires a new receiver clock generation; values from
two generations are not compared. If the evaluator cannot establish its own
clock continuity, it reports monitoring blindness and cannot preserve
`CURRENT`.

### Network partition and common-cause failure

A partition causes expiry and `UNKNOWN`, not preservation of the last positive.
Several observers may fail together or repeat one shared upstream source. A
count of observer IDs is not evidence of independence; policy can label failure
domains, but V1 treats those labels as configuration rather than proven fact.

### Quorum laundering

An attacker or correlated failure may create a reassuring majority against one
grounded contradiction. Contradiction records are not majority-voted away.
Resolution requires an explicit named act and fresh evidence is still required
for later `CURRENT`.

### Monitor-plane overload

Input flood, full queues, oversized frames, excess signal fields, or excessive
observer cardinality may impair observation. Wire frames and per-frame
collections are bounded. The campaign receiver also bounds subjects,
consumers, observers, stream/incarnation histories, pending inputs, schedules,
context history, sparse custody, receipts, and active escalations. Saturation
refuses the occurrence without eviction and withdraws positive standing where
the lost premise affects observation capability. These are experimental local
bounds, not production denial-of-service protection; JSONL replay-file size is
still a harness concern. Overload cannot make prior evidence appear current.

V1 is in-memory and single-process. It does not claim crash durability for
current pulse state. Restart begins without inherited positive reliance.

### Reactor death and timer lateness

The actor can wake late, its mailbox can saturate, its condition-variable wait
can fail, its thread can unwind, or its owner can disappear. A late wake uses
actual receiver time and records overshoot. Mailbox saturation is latched
outside the full queue. Actor unwind, abandonment, response timeout, and
required-journal failure clear the shared live-standing surface. These paths
reduce availability and do not prove a scheduler-latency bound. Process
`SIGKILL` removes the entire live surface; restart has a new monotonic epoch and
begins `UNKNOWN` with no evidence or deadline.

### Journal tear, corruption, and rollback

Process death may leave a partial header, payload, trailer, commit marker, or a
fully written but uncommitted suffix. Recovery validates exact lengths,
sequence, prior links, frame checksums, commit checksums, and closed payload
types, then stops at the first defect. It never hunts later bytes for a record.
An allowed valid prefix is explicitly incomplete and requires operator action;
interior corruption and other refused outcomes cannot project history.

The format cannot authenticate a malicious writer or detect removal at an
exact committed-record boundary without an external trusted tail anchor. A
compromised storage layer can therefore hide history. It still cannot restore
present reliance because restart never projects historical events into
`CURRENT`, support, deadlines, active escalation ownership, or mutation
authority.

The bounded receiver runtime treats policy rollback, equal-content
regeneration, identifier ABA, stale deadline callbacks, and deserialized
historical `CURRENT` transitions as substitution attacks. Context activations
and support certificates bind the complete generation set. Restart loads only
history and installs `UNKNOWN`.

Queue, observer, stream, incarnation, deadline, and history cardinality are
hostile inputs. Saturation is a typed refusal and observation-capability loss,
not an eviction hint. The campaign does not qualify behavior after process
memory exhaustion, OS scheduler failure, or a compromised receiver clock.

### Artifact substitution and authority laundering

An input may reuse a generation label while replacing executable, evaluator,
policy, profile, observer-set, observation-policy, configuration, contract,
corpus, or qualification-result bytes. It may pair an old certificate with a
new manifest, replay a prior process receipt, supply noncanonical JSON with
equivalent apparent meaning, or assert an unconfigured revocation. The binding
gate treats each as a substitution or ambiguity and withholds `CURRENT`.

Exact hashes establish only content identity under their algorithm
assumptions. A canonical manifest is not qualification; a checked certificate
is not activation; and a historical receipt is not a live process capability.
The local certificate is unsigned, executable measurement is self-observation
through a retained `/proc/self/exe` handle, and no package object grants
continuation, diagnostic execution, deployment, signing, revocation, or
mutation authority. A malicious kernel, loader, compiler, build environment,
or process-memory writer remains outside the established claim.

### Receiver-boundary substitution and replay

An attacker may possess an unaccepted key, corrupt or truncate a datagram,
reuse a signature in another domain, substitute package, activation, observer,
failure-domain, receiver, subject or incarnation identities, replay an old
challenge or envelope, reset sequence, flood a bounded queue, or present a
competing sender occurrence. The V1 canary uses exact pinned Ed25519 keys,
five distinct signature domains, canonical bounded PCN1 bodies, process-bound
offer and challenge state, a receiver-signed session acceptance, a fixed
replay bitmap, and fail-closed queue/session bounds.

This establishes configured-key possession over exact bytes and local
receiver admission only. A stolen or shared key, malicious sender host, false
observation, configured-but-fictitious failure-domain label, pre-arrival
delay, packet denial, kernel compromise, traffic analysis, and endpoint or DNS
spoofing remain outside the claim. Network metadata never supplies authority.

### Escalation storms

Equivalent failures may repeatedly cross a threshold. A stable semantic key
deduplicates active requests until expiry and records the suppressed count.
Deduplication cannot extend request expiry. Changed subject, consumer, policy,
trigger, or requested profile forms a distinct semantic request.

### Diagnostic authority injection

An evaluator or agent may attempt to supply a shell command, broader scope,
longer runtime, or mutation target. The request type has no such fields. The
bridge selects from a closed compiled registry, can only narrow bounds, and
refuses expired or unknown requests. The stub invokes no shell.

### Misleading diagnostic completion

A completed diagnostic may be treated as proof of lasting health. Receipts are
scope- and time-bound auxiliary evidence. Recording one never resets pulse
freshness, resolves contradiction implicitly, or changes the judgment to
`CURRENT` by itself.

### Presentation collapse

A UI may hide missing coverage behind a green color or compress dimensions to
a score. The versioned judgment carries categorical status, dimensions,
coverage, exact reasons, and nonclaims. A future UI remains responsible for
showing them; V1's terminal output is intentionally textual and explicit.

## Security properties not claimed

V1 does not defend against a compromised evaluator host, forged identity under
the placeholder authentication mode, colluding Byzantine observers, traffic
analysis, denial of service beyond local bounds, rollback of process memory,
or a malicious replacement bridge binary. It does not establish clock
synchronization, remote one-way delay, observer independence, or coverage
truthfulness.

These are not reasons to infer health. They are reasons a stricter consumer
will remain `UNKNOWN`.

## Safe failure posture

On malformed input, unsupported schema, unknown policy generation, clock
incomparability, capacity exhaustion, or internal observation loss, the
runtime emits a bounded refusal/degradation fact and withholds `CURRENT`.
Failure may reduce availability; it must not strengthen a claim.
