# Receiver-boundary custody campaign plan

Status: written before campaign-5 implementation on 2026-08-04.

Starting commit:
`94c4c8ee8e7de89edee212abc823e97c809fc26a`.

1. Freeze the receiver-boundary contract: exact pinned-key identities,
   canonical signed offer/challenge/binding/receiver-acceptance/envelope
   objects, live non-serializable session custody, receiver-local admission
   receipts, arrival-anchored freshness, total admission order, explicit
   bounds, and restart loss.
2. Add the smallest schema and runtime seams: a receiver-boundary policy digest
   inside the existing qualified runtime-configuration artifact, a bounded
   remote-custody reference in support certificates, and a move-only verified
   remote input that cannot be constructed from historical bytes.
3. Implement one Ed25519-pinned UDP canary with a fixed 1,232-byte datagram
   ceiling, fixed queues, one live peer session, strict replay/sequence and
   competing-occurrence handling, and no general RPC or async framework.
4. Integrate accepted evidence with the evaluator, deterministic scheduler,
   local reactor, sparse journal, contradiction custody, lifecycle barriers,
   and restart law. Sender emission and receiver challenge/admission each
   recheck the live local qualified activation through the reactor actor.
5. Qualify substitution, canonical encoding, authentication domains, replay,
   gaps, bounds, silence/expiry, overload, lifecycle, competing occurrences,
   and process-kill boundaries. Generate checked machine-readable artifacts
   and deterministic terminal demos.
6. Run an actual two-host canary only if a second explicitly configured,
   reachable, user-controlled Linux host exists. Otherwise preserve that as a
   named unexecuted obligation and make no two-host claim.
7. Run formatting, strict Clippy, and all workspace tests; commit coherent
   milestones locally; leave the standalone repository clean with no remote
   and nothing pushed.

The campaign stops rather than weakening receiver-owned freshness, exact
qualified activation, crash-honest restart, boundedness, contradiction
custody, or the no-authority boundary.
