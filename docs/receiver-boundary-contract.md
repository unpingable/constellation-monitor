# Bounded receiver-boundary and observation-custody contract

Status: normative for campaign 5. Names and wire tags remain provisional.

## Owned question and judgment separation

This campaign owns one deliberately narrow path:

> Can one qualified local sender process transfer one exact bounded pulse to
> one qualified local receiver process through one pinned-key authenticated
> UDP session, while the receiver retains sole custody of admission, arrival,
> freshness, coverage interpretation, reliance, and expiry?

The following are independent facts:

```text
configured Ed25519 key possessed and signature valid
!= sender assertion of one qualified local activation
!= receiver admission of one exact envelope
!= one consumer's current reliance judgment
```

No network object contains `CURRENT`, health, continuation authority, transport
administration, diagnostic-execution authority, deployment authority, signing
authority, revocation authority, or mutation authority.

## Exact key identity and private-key law

`PeerKeyIdentityV1` binds protocol version, closed Ed25519 algorithm, exact
32-byte public key, its domain-separated SHA-256 content identity, closed
sender/receiver role, intended peer role, bounded accepted subject scope, and
the exact local peer-policy identity that pins it. Endpoint, DNS and hostname
metadata are never part of key authority.

Ed25519 signatures use `ed25519-dalek` 2.2 with strict verification. A valid
signature proves only possession of the configured private key over the exact
domain-separated canonical bytes. It does not prove organizational identity,
authorization, host/process integrity, qualified code execution, observation
truth, failure-domain independence, key secrecy, exclusive custody, or remote
attestation.

Signing keys are live non-serializable objects. Test keys are deterministic
fixtures. Live keys may be created only in a newly created mode-0600 temporary
file and are removed after the bounded exercise. Private bytes are never
logged, journaled, committed, printed, or included in qualification artifacts.

## Canonical signed protocol

The network protocol is compact canonical binary, not JSON. Every datagram is:

```text
magic PCN1
protocol version u16
closed message-kind u8
exact body length u16
body fields in one schema-defined order
Ed25519 signature[64]
exact EOF
```

Integers are big-endian. Text is length-prefixed valid UTF-8 with a stricter
transport bound. Digests are encoded as exact 32-byte SHA-256 values and
reconstructed only in canonical lowercase `sha256:` form. Lists have explicit
bounded counts and canonical order. Payloads have an exact bounded length and
digest. There are no optional maps, field tags, alternate orderings, padding,
or trailing bytes. Truncation, unsupported tags/versions, invalid UTF-8,
length disagreement, unknown values, and extra bytes are refused.

Signatures cover a length-framed transcript of one exact ASCII domain and the
exact canonical body bytes. The only V1 domains are:

```text
monitor.receiver-session-challenge.v1
monitor.sender-session-binding.v1
monitor.observation-custody-envelope.v1
```

A signature from one domain must fail in every other domain. Signed-object
digests include the exact domain, body and signature. JSON encodings used in
fixtures and historical receipts are bounded display/artifact encodings, not
alternate signed bytes.

## Datagram and queue bounds

The canary uses one UDP socket per role, one pinned peer, and no discovery,
connection framework or async runtime. `MAX_CANARY_DATAGRAM_BYTES` is 1,232
bytes, fitting the IPv6 minimum link MTU after IPv6/UDP headers. The receiver
uses a fixed 1,233-byte buffer so an oversized/truncated datagram is observed
as over-bound and rejected. The sender never passes an over-bound datagram to
the socket. The protocol does not perform fragmentation or reassembly and does
not claim an arbitrary path MTU.

Sender and receiver application queues have exact nonzero capacities from the
qualified transport policy. Saturation refuses without eviction. Receiver
saturation or an unobservable receive path is reported to the reactor as
transport blindness, removing the live positive surface. Socket errors,
malformation, authentication, semantic refusal and subject contradiction stay
separate failure classes.

## Load-bearing transport policy

`RuntimeConfigV1.transport_custody_policy` optionally binds one closed local
role, policy generation and exact canonical policy digest. Because runtime
configuration is an activation-required artifact, a sender/receiver canary
may operate only when its exact typed policy hashes to that qualified field and
the reactor freshly revalidates its live `QualifiedAndMatched` activation.
Legacy/local-only runtimes use `None` and cannot create a transport session.

The receiver policy pins the sender/receiver key identities, accepted sender
manifest/certificate, protocol/schema, observer, configured failure-domain
claim, subject scopes, observation kinds, datagram/session/message/rate/queue,
replay and gap bounds, local lifecycle authority/status, and
`ArrivalAnchored` admission posture. The sender policy pins the exact receiver
key and acceptance-policy identity plus its permitted observer, failure domain
and subject/kind scope.

Policy change invalidates every session, declares affected remote custody
blind, withdraws standing and deadlines, and requires a newly qualified local
activation plus a new challenge/binding. A command-line label or equal policy
body under another generation is insufficient.

## Receiver challenge

`ReceiverSessionChallengeV1` is receiver-signed and binds the receiver key,
live qualified process occurrence, monotonic epoch, fresh 32-byte random nonce,
exact receiver policy generation/digest, intended sender key, accepted sender
manifest/certificate, receiver-monotonic issuance and inclusive expiry,
datagram/message limits, and domain. It is emitted only after a live reactor
activation recheck.

The sender verifies canonical bytes, receiver signature and exact pinned
receiver/policy identities before responding. Challenge lifetime is evaluated
against the receiver times carried for protocol comparison only; the sender
does not use those values as evidence freshness. The receiver remains the
authority for session expiry. A challenge is bound to one receiver process and
epoch, one intended sender, one policy and one message bound. Restart or policy
replacement destroys the live nonce/session state, so historical bytes cannot
recreate it.

## Sender binding

`SenderSessionBindingV1` is sender-signed and binds the challenge, both exact
key identities, sender process occurrence and monotonic epoch, sender manifest,
qualification certificate and activation receipt, exact runtime generation
set, observer/failure-domain claim, permitted subject scopes, observation
protocol and sequence origin. Its result is explicitly an authenticated
`qualified_and_matched_assertion`, not receiver verification of remote
execution.

The sender creates it only by synchronously asking its reactor to revalidate
the non-serializable local activation. The receiver verifies its locally held
canonical sender qualification package and pins the manifest/certificate,
then records the live activation receipt/process values as authenticated sender
assertions. A historical receipt cannot invoke this API.

## Observation envelope

`ObservationCustodyEnvelopeV1` is sender-signed and binds challenge/session,
both key identities, sender process/epoch and exact manifest/certificate/
activation, observer/failure-domain, subject/incarnation, observation identity
and sequence, session sequence, closed `pulse_v1` kind, exact compact pulse
wire bytes and digest, and sender observation/emission monotonic values.

Sender times are provenance only. The envelope carries neither receiver arrival
nor remaining freshness nor judgment. Before every envelope the sender
rechecks local qualified activation, reactor operational state, session expiry
and message bound, exact scope/kind, payload canonicality and queue capacity.
Failure closes the session and emits no reassuring terminal observation.

## Deterministic receiver admission

The receiver verifies in this total order:

1. fixed transport size/framing;
2. canonical binary decoding and protocol/schema;
3. challenge and live session identity;
4. intended receiver and pinned sender key;
5. strict domain-separated signature;
6. sender process occurrence;
7. exact manifest/certificate/activation identities;
8. observer and configured failure-domain claim;
9. subject scope/incarnation and observation kind;
10. session and observation sequence/replay state;
11. queue, rate and all capacity bounds;
12. pulse length, digest and canonical wire decoding;
13. accepted local lifecycle state; and
14. receiver-owned evidence-admission posture.

Failure returns one complete typed `ReceiverAcceptanceReceiptV1`; it produces
no verified remote token. Success creates a move-only, non-serializable
`VerifiedRemoteObservationV1`. Only that live token can become
`RuntimeInputV1::RemotePulse`; caller-created receipts, envelopes or generation
labels cannot invoke the remote evidence path.

The runtime attaches its own arrival annotation, admits the pulse through the
existing evaluator, records the acceptance receipt as a sparse historical
event, and adds an exact bounded `RemoteObservationCustodyReferenceV1` to every
support certificate actually using that evidence. The reference names sender,
receiver, policy, challenge, session, envelope, both packages/activations/
process occurrences, observer, subject/incarnation/sequences, payload,
receiver arrival and accepted evidence identity. A receipt alone remains
history and is not support.

## Freshness and first-seen delay

V1 remote evidence mode is exactly `ArrivalAnchored`:

```text
support expiry = receiver arrival + min(sender-declared validity,
                                        consumer maximum validity)
```

Inclusive expiry and reactor lateness retain their existing laws. Sender
timestamps, retry, duplicate delivery, replay, reorder, session rebind and
round-trip measurements cannot move the original admitted arrival or deadline.
Receiver queueing after arrival consumes support time. Silence and partition
allow support to expire to `UNKNOWN`; they do not create subject contradiction.

A first-seen observation delayed wholly before receiver arrival remains
indistinguishable from prompt delivery without separate qualified one-way-delay
evidence. The challenge narrows replay to a live occurrence but does not prove
observation age. Any policy requiring observation-time freshness therefore
gets `UNKNOWN`; RTT, LAN samples and sender clocks cannot manufacture a bound.

## Replay, gap and competing-occurrence law

Each one-session state holds a fixed replay-window bitmap, session high-water,
observation high-water, bounded gap facts and accepted-message count. Exact
duplicates and seen older sequences are refused and do not reach the runtime.
Unique reorder within the bounded window is recorded and refused rather than
refreshing evidence. A forward gap within the configured bound may be admitted
only with explicit gap status; a larger gap is refused and marks missingness.
Sequence overflow, reset without a new session, prior-session/process/receiver
replay, changed subject/observer, and message-count exhaustion are refused.

One observer/key/scope cannot have two overlapping sender process occurrences.
A second occurrence creates `SenderOccurrenceConflict`, withdraws affected
standing, preserves both assertions historically, invalidates the session and
admits neither. Replacement requires explicit retirement followed by a fresh
challenge and session; last arrival never chooses a winner.

## Failure vocabulary

The closed statuses include `TransportUnavailable`, `TransportOverloaded`,
`TransportMalformed`, `AuthenticationFailed`, `ReceiverChallengeInvalid`,
`SessionExpired`, `SessionUnknown`, `SessionConflict`,
`SenderOccurrenceConflict`, `SignatureInvalid`, `QualifiedIdentityMismatch`,
`CertificateSuperseded`, `CertificateRevoked`, `ReplayDetected`,
`DuplicateDetected`, `SequenceGap`, `ObservationRejected`, `PayloadMalformed`,
`SubjectScopeMismatch`, `ObserverRoleMismatch`, `ReceiverBlind`, and
`EvidenceAdmitted`. They are findings about custody/admission, not one scalar
subject status.

## Restart, crash and historical custody

Sender restart yields `Unbound`, no session and no transport authority.
Receiver restart yields `Unbound / UNKNOWN`, zero sessions, accepted remote
activations, evidence and deadlines. Both use fresh process/monotonic epochs
and must reactivate locally, issue/verify a new challenge and establish a new
binding. Old bindings/envelopes are refused.

Historical challenge, session-binding, envelope and acceptance receipts may be
journaled as sparse facts. They cannot construct the move-only session or
verified remote token. Process death before/after signing, verification,
journaling, evaluator admission or `CURRENT` can lose history, but restart
never projects it into session, evidence, deadline, reliance, diagnostic
execution or mutation authority.

## Exact nonclaims

This contract does not establish remote attestation; kernel, loader, firmware
or host integrity; secure boot; TPM identity; key secrecy or exclusive custody;
signer authorization; public PKI or organizational identity; DNS, endpoint or
route authority; confidentiality or traffic-analysis resistance; denial-of-
service resistance beyond explicit bounds; sender truthfulness; observer or
failure-domain independence; complete coverage; synchronized clocks;
sender-clock freshness; bounded one-way delay or first-seen age; delivery,
ordering or availability; Byzantine correctness or consensus; multi-hop,
multi-receiver or arbitrary multi-sender custody; production transport or
deployment; hard real time; physical-media durability; subject health;
product-plane status; or continuation, transport administration, diagnostic,
deployment, signing, revocation or mutation authority.
