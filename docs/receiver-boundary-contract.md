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

Signing keys are live non-serializable objects. Qualification keys are
generated from operating-system randomness; the hostile harness deliberately
creates two in-memory holders of one ephemeral key and therefore makes no
exclusive-custody claim. A live canary key file may be created only as a new
mode-0600 temporary file and is removed after the bounded exercise. Private
bytes are never logged, journaled, committed, printed, or included in
qualification artifacts.

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
monitor.sender-session-offer.v1
monitor.receiver-session-challenge.v1
monitor.sender-session-binding.v1
monitor.receiver-session-acceptance.v1
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
`ArrivalAnchored` admission posture. Its identity is a domain-separated digest
of (a) a canonical cycle-free anchor containing every field except the accepted
sender manifest/certificate and (b) those two exact sender-package digests.
The sender policy pins that exact anchor as well as the receiver key and policy
generation. The challenge supplies the full composite identity and exact
sender-package pair, so the sender recomputes it. This avoids a content-hash
cycle while refusing same-label receiver-policy substitution.

Policy change invalidates every session, declares affected remote custody
blind, withdraws standing and deadlines, and requires a newly qualified local
activation plus a new offer/challenge/binding/acceptance handshake. A
command-line label or equal policy body under another generation is
insufficient.

## Sender offer and occurrence binding

`SenderSessionOfferV1` is the bounded preflight needed to make a later
receiver challenge non-replayable across sender restart. It is sender-signed
and binds a fresh random sender nonce, intended receiver key, sender key, live
sender process occurrence and monotonic epoch, exact manifest, qualification
certificate, activation receipt and runtime-generation set, plus the
configured observer, failure-domain claim and subject scopes.

The sender creates an offer only after its reactor revalidates the live local
activation. The receiver verifies the exact pinned sender key and package
before issuing a challenge. An offer is an authenticated sender assertion,
not remote attestation or admitted evidence. The receiver keeps at most one
pending offer/challenge and never persists it as live state.

## Receiver challenge

`ReceiverSessionChallengeV1` is receiver-signed and binds the receiver key,
live qualified process occurrence, monotonic epoch, fresh 32-byte random nonce,
the exact sender-offer digest and intended sender process occurrence, exact
receiver policy generation/anchor/composite digest, intended sender key,
accepted sender manifest/certificate, receiver-monotonic issuance and inclusive expiry,
datagram/message limits, and domain. It is emitted only after a live reactor
activation recheck.

The sender verifies canonical bytes, receiver signature, exact pinned policy
anchor, and the recomputed composite receiver-policy identity before
responding. A matching generation label is never enough. Challenge lifetime is evaluated
against the receiver times carried for protocol comparison only; the sender
does not use those values as evidence freshness. The receiver remains the
authority for session expiry. A challenge is bound to one receiver process and
epoch, one exact live sender offer/process occurrence, one policy and one
message bound. A sender without the matching process-local pending offer
refuses it. Restart or policy replacement on either peer destroys the offer,
nonce and session state, so historical challenge bytes cannot recreate a
session.

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
assertions. A historical receipt cannot invoke this API. The sender binding is
provisional and cannot emit an observation until the next acknowledgement is
verified.

The deterministic harness packages are explicitly one-test semantic fixtures
used to exercise this exact activation gate; their certificates carry
`not_campaign_qualification_evidence`. Final workspace gates and hostile
results are separate campaign evidence. Because no authorized second Linux
host was available, this run does not claim that a cross-host deployed binary
was activated from a final campaign package.

## Receiver session acceptance

`ReceiverSessionAcceptanceV1` is the receiver-signed acknowledgement that
closes the live handshake. It binds the exact challenge and sender-binding
digests, both keys, both process occurrences, receiver monotonic epoch and
policy digest, receiver-owned inclusive session expiry, and message bound.
The sender verifies it against its process-local provisional offer, challenge
and binding and freshly revalidates local activation. Only then does the
sender count the session as live or permit envelope emission.

This acknowledgement is load-bearing: without it, an authenticated sender
could not know that the live receiver occurrence admitted its binding. It
proves receiver-key possession over exact bytes, not receiver host integrity,
receiver truthfulness, or transport authority.

## Observation envelope

`ObservationCustodyEnvelopeV1` is sender-signed and binds challenge/session,
both key identities, sender process/epoch and exact manifest/certificate/
activation, observer/failure-domain, subject/incarnation, observation identity
and sequence, session sequence, closed `pulse_v1` kind, exact compact pulse
wire bytes and digest, and sender observation/emission monotonic values.

Sender times are provenance only. The envelope carries neither receiver arrival
nor remaining freshness nor judgment. Before every envelope the sender
rechecks the signed receiver acceptance, local qualified activation, reactor
operational state, session expiry and message bound, exact scope/kind, payload
canonicality and queue capacity.
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
The refusal receipt preserves the exact `BoundExceeded` replay classification
rather than flattening it to generic replay.
Sequence overflow, reset without a new session, prior-session/process/receiver
replay, changed subject/observer, and message-count exhaustion are refused.

One observer/key/scope cannot have two overlapping sender process occurrences.
A second occurrence creates `SenderOccurrenceConflict`, withdraws affected
standing, preserves both assertions historically, invalidates the session and
admits neither. Replacement requires explicit retirement followed by a fresh
challenge and session; last arrival never chooses a winner.

## Failure vocabulary

The closed statuses include `TransportUnavailable`, `TransportOverloaded`,
`TransportMalformed`, `AuthenticationFailed`, `SenderKeyMismatch`,
`ReceiverChallengeInvalid`,
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
and must reactivate locally, create and verify a new sender offer, issue and
verify a new challenge, establish a new binding, and verify a new receiver
acceptance. Old offers, challenges, bindings, acceptances and envelopes are
refused.

Historical offers, challenges, session bindings, receiver acceptances,
envelopes and admission receipts may be journaled as sparse facts. They cannot
construct the move-only session or verified remote token. Process death before
or after signing, verification, journaling, evaluator admission or `CURRENT`
can lose history, but restart never projects it into session, evidence,
deadline, reliance, diagnostic execution or mutation authority.

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
