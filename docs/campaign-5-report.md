# Receiver-boundary custody campaign report

Status: qualified local experimental result on 2026-08-04; the actual
two-Linux-host canary remains unexecuted. Repository, protocol, and record names
remain provisional.

## Baseline, reconnaissance, and commit sequence

The campaign began from exact clean commit
`94c4c8ee8e7de89edee212abc823e97c809fc26a` on `main`, with no remote. The
baseline passed all required gates with 125 tests. Reconnaissance read every
required contract, report, artifact, runtime/activation/reactor/journal API,
and test surface before implementation. It found a lawful extension seam:
transport policy could become part of the already-qualified runtime
configuration, while sessions, replay state, accepted evidence, and deadlines
remained process-local and non-serializable.

The implementation sequence before this report/artifact commit is:

```text
235b3ef Define receiver-boundary custody contract
5749060 Add bounded receiver-boundary custody runtime
6b813a8 Tighten custody qualification and demos
bfbaa00 Bind sender to exact receiver acceptance policy
64af479 Make reorder qualification expiry-aware
9b25f15 Qualify transport replay and rate bounds
```

The exact implementation commit named by the checked campaign artifact is
`9b25f156286963c6cdc63892a4d60ad69d802207`, Git tree
`f9d574cc1b908b4fc26376d2be12d1a3ae0b11b0`. The final report/artifact commit
is necessarily identified by Git rather than embedding its own hash here; the
completion handoff names it.

The bounded neighboring comparison remained read-only at these exact clean
commits: NQ-NG `59abd3bcb2d0cc30657a659b3ebc57b981289d9f`, Witness
`e3d22f9bef8dc248e58e0fa5b7fa474b2dd78c5d`, Nightshift
`500f4b7bd4f066c7ca43963d192f314559cdbc83`, Docket
`3ce07f9bb3be6ba86ca65f3b521f807970b56119`, and Synesthesia
`d1a731c383d4fce8f9bc21f40b63af5dbae2aa94`. Exact inspected paths and the
limited concepts compared are in `campaign-5-reconnaissance.md`. No neighboring
repository was modified, no schema or authority was imported, no remote was
created, and nothing was pushed.

## Architecture and mechanism

The campaign adds one `pulse-transport-canary` crate and one narrow custody
module in `pulse-runtime`. It is exactly one sender, one receiver, one pinned
peer per side, one live session, one `pulse_v1` observation kind, and one
bounded UDP datagram path. It does not introduce an async runtime, RPC layer,
discovery, networking service, or general agent API.

The live custody chain is:

```text
sender local QualifiedAndMatched activation
  -> signed process/package offer
receiver local QualifiedAndMatched activation + exact acceptance policy
  -> signed process-bound challenge
sender exact policy/activation revalidation
  -> signed qualified-activation assertion binding
receiver exact package/occurrence verification
  -> signed receiver session acceptance
sender exact activation/session revalidation
  -> signed exact observation envelope
receiver canonical/authentication/identity/replay/capacity admission
  -> receiver-local arrival + historical acceptance receipt
  -> move-only VerifiedRemoteObservationV1
  -> ordinary consumer-indexed evaluator
  -> support certificate naming exact remote custody
  -> receiver reactor owns inclusive expiry
```

The offer is necessary because an old receiver challenge cannot bind a new
sender occurrence. The receiver-signed acceptance is necessary because a
provisional sender binding cannot assume the receiver activated it. Neither
message is remote attestation. Transport authentication, sender assertion,
receiver admission, and consumer reliance remain four distinct records.

## Authentication, key identity, and private material

The only message-authentication algorithm is Ed25519 through
`ed25519-dalek` 2.2 with `verify_strict`. `rand_core` 0.6 with `getrandom`
obtains operating-system randomness. No cryptographic primitive is implemented
locally.

`PeerKeyIdentityV1` binds the exact 32-byte public key and domain-separated
SHA-256 digest, Ed25519 algorithm, protocol version, closed sender/receiver
role, intended peer role, bounded scope, and local acceptance-policy identity.
A network address, hostname, DNS record, route, or interface is metadata only.
A valid signature means possession of one configured key over exact bytes; it
does not establish signer authority, exclusive custody, host integrity, code
execution, or observation truth.

The final public artifact identities are:

```text
sender key   sha256:a0867f97772475775ede2d7f9ac31135ad2091c918392947a81d8a4810beb12f
receiver key sha256:a556ad1f1be96aeedca4027f3ac3e874bb4f7ab425e78d80c20c9e17f7781e49
```

Signing keys are non-serializable in-memory values. The Linux file exercise
creates a new mode-0600 temporary private-key file and removes it on drop. The
hostile harness intentionally duplicates one ephemeral key in memory, proving
that no exclusive-key-custody claim is made. Searches and artifact tests found
no private bytes in logs, journals, committed files, or reports.

## Canonical wire and signature domains

Each PCN1 datagram is at most 1,232 bytes:

```text
magic[4] | protocol u16 | closed kind u8 | body length u16
| schema-ordered canonical body | Ed25519 signature[64] | EOF
```

Integers and lengths are big-endian. Text is nonempty, bounded, control-free
UTF-8 prefixed by an exact u16 length. Digests are exact 32-byte SHA-256 values;
payloads and scope lists have explicit bounded lengths/counts. There are no
maps, field tags, alternate orderings, padding, or trailing bytes. Policies
use strict compact canonical JSON with `deny_unknown_fields`, duplicate-field
rejection, re-encoding equality, and fixed declaration order; JSON is not an
alternate signed wire encoding.

Signatures cover `u16(domain length) | exact ASCII domain | u64(body length) |
body`. The five closed domains are:

```text
monitor.sender-session-offer.v1
monitor.receiver-session-challenge.v1
monitor.sender-session-binding.v1
monitor.receiver-session-acceptance.v1
monitor.observation-custody-envelope.v1
```

Cross-domain verification fails. SHA-256 content and signed-object digests
provide identity/corruption detection under collision-resistance assumptions;
they do not establish authorship, qualification, freshness, or authority.

## Exact transport policy and session protocol

The local runtime activation manifest already includes exact runtime
configuration. Campaign 5 adds an optional closed transport-policy binding to
that configuration. A legacy `None` runtime cannot open a custody session.

The receiver policy pins both keys, exact sender manifest/certificate,
protocol/schema, observer, configured failure-domain claim, subject/kind
scope, 1,232-byte frame ceiling, session/message/rate/queue bounds, replay and
gap bounds, lifecycle status/authority identifier, journal identity, and
freshness posture. The sender pins the receiver key and an exact cycle-free
receiver-policy anchor. The full receiver-policy identity is a
domain-separated digest of that anchor plus the exact admitted sender manifest
and certificate. The challenge carries both; the sender recomputes the full
identity. This breaks the qualification-package hash cycle without allowing a
generation label or same-label policy substitution to stand in for content.

The canary fixture uses a 750 ms session lifetime, 16 messages/session,
16 messages/second, eight-entry sender and receiver queues, a 16-position
replay bitmap, maximum sequence gap eight, 640-byte pulse payload ceiling, and
120 ms observation validity. Type-level ceilings are 1,232-byte datagrams,
64-entry queues, 64-position replay windows, eight scopes, 256-byte text, and
256 retained acceptance receipts. Every exhausted bound refuses; none evicts
silently.

Sender offer, challenge, binding, receiver acceptance, and observation
envelope each name exact peer keys and process occurrences appropriate to
their role. The binding/envelope additionally name the sender manifest,
certificate, activation receipt, generation-set digest, process-local
monotonic epoch, observer/failure-domain claim, and subject scope. The envelope
also names subject incarnation, observation/session sequences, exact payload
and digest, and sender-local provenance times. It carries no receiver arrival,
judgment, health, or operational authority.

## Sender emission and receiver admission law

Before offer creation, binding, receiver-acceptance processing, and each
envelope, the sender synchronously asks its reactor to revalidate the exact
non-serializable `QualifiedAndMatched` activation and transport-policy binding.
It also checks reactor custody, exact peer/policy/session identity, inclusive
session expiry, message count, scope/kind, canonical payload, and queue
capacity. Any mismatch, lifecycle withdrawal, blindness, overload, or
termination invalidates the session and stops successful emission. There is no
terminal reassuring pulse and no serialized transport authority.

The receiver processes one queued envelope in this fixed order: frame bound;
canonical decode/protocol; challenge/live session; intended receiver and
pinned sender key; strict signature; sender process; manifest/certificate/
activation identities; observer/failure-domain; subject/incarnation/kind;
session and observation sequence/replay; queue/rate/capacity; payload
length/digest/canonical pulse; lifecycle; and receiver-owned admission
posture. A failure creates a complete typed historical refusal and no verified
token. Only the move-only `VerifiedRemoteObservationV1` can construct the
remote runtime input.

An accepted receipt records receiver process/epoch/policy, arrival, endpoint
metadata, each admission result, gap/replay result, exact evidence identity,
sequence/journal identity, and no mutation authority. The support certificate,
not the envelope or receipt, records whether a named consumer currently relies.
When it does, its bounded remote reference names both keys, both manifests/
certificates/activation receipts/process occurrences, sender offer, challenge,
binding, receiver acceptance, envelope/payload, observer, subject/incarnation,
sequences, receiver arrival, and acceptance receipt.

## Freshness, replay, gap, and occurrence semantics

V1 is explicitly `ArrivalAnchored`:

```text
support expiry = receiver arrival
               + min(sender-declared validity, consumer validity bound)
```

Arrival is receiver monotonic time. Sender wall or monotonic values are
provenance only. Queueing after arrival consumes support. Retry, duplicate,
new-envelope observation replay, reorder, and stale replay cannot change the
admitted arrival or deadline. The dedicated receiver reactor withdraws
`CURRENT` at inclusive expiry without a new packet. Network silence/partition
removes support but does not invent a subject contradiction.

One fixed bitmap/high-water state refuses duplicate/replay/reorder without an
unbounded historical set. A forward gap within the exact bound may be admitted
only with the precise missing range. An over-bound gap is refused and its
receipt preserves `BoundExceeded` rather than flattening it to a generic
status. Sequence reset, count/rate exhaustion, and replay from the wrong
session/process/receiver/package/scope are refused. Duplicate or replay does
not reach the evaluator and cannot duplicate escalation.

Two overlapping sender process occurrences claiming the same observer, key,
and scope create `SenderOccurrenceConflict`. The receiver invalidates custody,
withdraws the positive surface, preserves both assertions historically, and
does not choose the last packet. Replacement requires a fresh offer/challenge/
binding/acceptance sequence.

The preserved limitation is material: an observation delayed entirely before
its first receiver arrival is indistinguishable from prompt delivery. The
challenge prevents pre-session reuse and ties the envelope to one receiver
occurrence; it does not prove one-way delay or observation age. A consumer
requiring observation-time freshness gets `UNKNOWN`. Sender clocks, RTT, LAN
measurements, and configured latency guesses do not manufacture that premise.

## Restart, history, lifecycle, and contradiction custody

Sender or receiver restart creates a new process/monotonic epoch and restores:

```text
binding state = Unbound
live sessions = 0
accepted remote activations = 0
current standing = UNKNOWN
supporting evidence = 0
active deadlines = 0
active transport/diagnostic/mutation authority = none
```

Historical offers, challenges, bindings, receiver acceptances, envelopes,
admission receipts, support transitions, activation receipts, contradictions,
and diagnostic receipts may be recovered. None constructs the live signing
identity, session, replay window, verified evidence token, support, or
deadline. Both peers must reactivate locally and complete a new handshake.

An exact locally configured lifecycle fact can supersede or revoke the pinned
sender certificate. Either invalidates the session, positive standing, and
deadline while preserving history. A fact from an arbitrary authority string
is refused. This is a local acceptance boundary, not global revocation
authority. Diagnostic acceptance or completion retains the existing
contradiction custody and grants no execution or mutation authority.

Real Linux `SIGKILL` was executed at three requested exact states: sender while
`QualifiedAndMatched`, after envelope signing/before delivery, and receiver
while remote evidence was `CURRENT`; an additional kill occurred with both
session states live before evidence. All recovered only history and no live
custody. Ten requested instruction-level points were not exposed as stable
kill boundaries: challenge-created/pre-send; challenge-verified; binding-
created/pre-send; binding-verified/pre-activation; receive/pre-signature;
signature/pre-admission; receipt-created/pre-journal; receipt-journal/pre-
evaluator; evidence/pre-certificate-journal; and SIGKILL within clean shutdown.
They are recorded as unexecuted, not inferred from broader points.

## Exact earned claims

Within the bounded local qualification scope, the campaign earns all 22
required semantic claims:

1. Transport authentication, sender activation assertion, receiver acceptance,
   and consumer reliance are distinct states and records.
2. Endpoint/hostname metadata cannot establish observer identity.
3. A valid signature establishes only configured-key possession over exact
   domain-separated bytes.
4. Both protocol roles verify exact locally pinned public-key identities.
5. The sender's successful offer/binding/envelope paths require a live local
   `QualifiedAndMatched` activation and operational reactor.
6. Receiver admission requires the exact accepted sender package and live
   sender occurrence.
7. Every admitted observation and support reference names the exact manifest,
   certificate, activation, occurrence, session, observer, subject,
   incarnation, sequences, and payload.
8. Receiver monotonic arrival owns remote evidence admission and expiry.
9. Sender time cannot renew or extend receiver freshness.
10. Duplicate, replay, reorder, observation reset, and retry cannot renew
    freshness.
11. Sequence gaps remain explicit; over-bound gaps remain explicit refusals.
12. Partition/silence expires standing without inventing subject
    contradiction.
13. Sender/receiver queue, rate, and message overload cannot remain invisible
    while positive custody continues.
14. Sender or receiver process restart destroys live session custody.
15. Historical session/acceptance records cannot reconstruct evidence,
    deadlines, or `CURRENT`.
16. Accepted exact supersession/revocation invalidates affected sessions and
    standing; arbitrary lifecycle assertions do not.
17. Competing sender occurrences cannot silently co-represent one observer or
    win by last arrival.
18. An authenticated envelope with any qualified-identity mismatch is refused.
19. The sender's qualified-activation statement remains an authenticated
    assertion, not remote attestation.
20. Failure-domain identity remains a configured claim, never independently
    proved.
21. First-seen pre-arrival delay remains unbounded without separate qualified
    evidence; observation-time freshness is refused.
22. No emitted object grants continuation, transport administration,
    diagnostic execution, deployment, signing, revocation, or mutation
    authority.

These are implementation/semantic claims from a local two-process-shaped
harness and real local process/UDP exercises. They are not a claim that the
same chain was deployed and observed between two Linux hosts.

## Exact refused claims and nonclaims

The campaign explicitly refuses an actual two-Linux-host qualification because
no second authorized reachable Linux host was available. It also refuses
independent verification of the sender's activation, qualified one-way delay,
first-seen observation age, failure-domain independence, endpoint authority,
network confidentiality, key secrecy/exclusive custody, full network fault
measurements, production transport security/availability, and the ten
unexposed exact crash boundaries listed above.

It does not claim remote attestation; kernel, loader, firmware, host, secure-
boot, or TPM integrity; key secrecy or exclusive custody; signer authorization;
public PKI or organizational identity; DNS authenticity or network endpoint
authority; confidentiality or traffic-analysis resistance; denial-of-service
resistance beyond explicit local bounds; sender observation truthfulness;
observer or failure-domain independence; complete coverage; synchronized
clocks; sender-clock freshness; bounded one-way delay or first-seen age;
packet delivery, ordering, or network availability; Byzantine correctness;
distributed consensus; multi-hop, multi-receiver, or arbitrary multi-sender
custody; production transport security or deployment viability; hard-real-time
behavior; physical-media durability; subject health; product-plane status; or
continuation, diagnostic-execution, deployment, signing, revocation, or
mutation authority.

It additionally does not claim remote source-to-binary correspondence,
independent qualification of a sender host, a general RPC/transport framework,
service discovery, dynamic enrollment, trust-on-first-use, key rotation,
certificate authority, remote revocation service, deployment orchestration, or
remediation.

## Hostile qualification and results

The exact required commands passed:

```text
cargo fmt --all -- --check                                           PASS
cargo clippy --workspace --all-targets --all-features -- -D warnings PASS
cargo test --workspace --all-targets --all-features                 PASS (159)
```

The 159 tests are the 125 preserved baseline tests plus 34 new tests: 30 in
`pulse-transport-canary` (one artifact, three canonical/property, three Linux
crash/private-key, and 23 custody tests) plus four runtime custody unit tests.
Property/corpus coverage includes every truncation and every single-byte
corruption across the five-message corpus, 128 arbitrary bounded datagrams,
signature-domain separation, strict canonical policy decoding, duplicate
multiplicity, same observation in a new envelope, reorder, gap/bound, exact
identity substitution, same-label receiver-policy substitution, session/rate/
queue exhaustion, expiry, old challenge, lifecycle, occurrence conflict, and
restart.

The checked machine-readable corpus is indexed under
`artifacts/receiver-boundary-custody/`. It contains protocol schemas, exact
public key/policy/package identities, five signed datagram corpora, acceptance,
authentication, replay/gap, occurrence, authority-refusal, crash/restart,
silence-expiry, local timing, two-host refusal, and qualification-summary
records. Artifact tests reparse every JSON object, verify exact package pairing
and all five signed datagrams, and reject any private-key material.

## Deterministic demos

Run:

```text
cargo run -p pulse-transport-canary -- demo
cargo run -p pulse-transport-canary -- expiry-demo
cargo run -p pulse-transport-canary -- restart-demo
```

The matched trace is:

```text
receiver Unbound -> QualifiedAndMatched (local semantic fixture)
sender Unbound -> QualifiedAndMatched (local semantic fixture)
signed sender offer
-> signed receiver challenge
-> signed sender binding
-> signed receiver session acceptance
-> exact 1,081-byte observation envelope
-> receiver acceptance receipt
-> Consumer A CURRENT, receiver deadline present
-> Consumer B UNKNOWN, no deadline
```

The expiry trace observed `CURRENT`, an exact receiver deadline, no further
envelope, reactor withdrawal at the inclusive deadline, zero active deadlines,
and `UNKNOWN` without a contradiction. The checked artifact sample requested
340 ms, withdrew at 341 ms, and reported 1 ms stale-positive overshoot.

The restart trace recovered 28 sparse records, one acceptance receipt, and one
historical `CURRENT` certificate, then reported `Unbound / UNKNOWN`, zero live
sessions, zero accepted remote activations, zero supporting evidence, and zero
active deadlines. A fresh activation and challenge were required.

Wrong-key, exact-package substitution, duplicate/replay, partition,
sender/receiver restart, competing occurrence, and first-seen-delay refusals
are deterministic named tests and machine artifacts rather than reassuring
prose-only examples.

## Live-host finding and measurements

The local Linux host was `sushi-k`, kernel `6.8.0-136-generic`, `x86_64`, with
default route interface `enx00242788ae45`. The only configured reachable
non-Git peer, SSH alias `mac`, reported Darwin 24.6.0 arm64 and therefore was
not represented as a second Linux host. No two-host keys or services were
staged, and no private cleanup was necessary there.

One real local UDP loopback probe sent the final 1,081-byte envelope between
ephemeral `127.0.0.1` sockets and observed exact byte preservation. The
separate local process-shaped sample recorded:

```text
session establishment                 120,052 us
emission through evaluator             53,968 us
expected withdrawal                        339 ms (epoch-local)
actual withdrawal                          339 ms (epoch-local)
stale-positive overshoot                     0 ms
resident set sample                     10,608 KiB
envelope                                  1,081 bytes
```

The separately generated silence demo observed 1 ms overshoot. These are
single local wall-clock samples, not distributions or bounds. Challenge RTT,
individual signature generation/verification, arrival-to-admission,
admission-to-evaluation, cross-host restart recovery, packet loss/reorder,
network partition, `tc netem`, CPU-load networking, memory under cross-host
load, and time to a new cross-host qualified session remain unmeasured because
the actual two-host exercise was not executed. LAN or loopback behavior is not
a production guarantee.

## Known semantic gaps and disposition

- The actual two-authorized-Linux-host custody path is unqualified.
- Sender activation is a signed exact assertion; the receiver does not
  independently attest sender execution or host integrity.
- `ArrivalAnchored` cannot bound first-seen pre-arrival delay.
- Failure-domain labels are configured claims, not independence evidence.
- The canary is one sender, one receiver, one observer path, one live session,
  and one observation kind; it does not establish multi-path continuity.
- UDP provides neither confidentiality, availability, delivery, nor ordering.
- Replay custody is process-local; restart intentionally discards it along with
  all accepted evidence and standing.
- Ten exact crash instruction boundaries remain unexecuted.
- The actual UDP probe exercised exact envelope byte custody, while the full
  five-message protocol was exercised by deterministic datagram transfer, not
  across a real network path.
- The deterministic activation packages are exact one-test semantic fixtures
  explicitly marked `not_campaign_qualification_evidence`; they are not a
  claim that final deployed sender/receiver binaries were activated from the
  campaign's final qualification package.

No formal stopping condition forced a semantic compromise. The unavailable
second Linux host triggered the specified honest refusal of the live two-host
claim. No previously earned claim was weakened; one timing-sensitive reorder
test was corrected to allow lawful autonomous expiry, and one hostile test
caused over-window refusal receipts to preserve their exact `BoundExceeded`
classification.

This remains a **useful runtime component**, not stronger product-category
evidence. It establishes a coherent local receiver-boundary custody mechanism,
but without a real two-host qualification and independent multi-path behavior
it does not justify product-plane language.

The single most defensible next campaign is the stated bounded
multi-observer/multi-failure-domain canary across three independently qualified
observation paths, beginning by executing the presently missing real two-host
custody obligation. That campaign should qualify receiver-side continuity and
conflict semantics without adding discovery, general RPC, or remediation.
