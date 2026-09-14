# Generic independent support for NQ project predicates v1

Status: original independent-source qualification is retained. The current
adapter targets the public NQ successor's compiled bounded-predicate boundary;
its connected qualification is required before advertising an installed profile.
This does not provide arbitrary catalog evaluation or a saved-check adapter.

## Layer and exact claim

The artifacts remain distinct:

```text
declaration != observation != NQ witness != NQ admission
            != Pulse current support != Nightshift attention
```

`pulse.project-predicate-qualified-support/v1` means only:

> At the explicit Pulse qualification occurrence, an exact positive NQ
> project-predicate admission replayed under its original inventory and
> catalog. A separately signed support observation matched an operator-owned
> source/subject/vantage policy, and NQ recomputed the same content-bound
> predicate over its typed facts. Both observation occurrences satisfied the
> policy's exclusive age bounds and maximum skew.

It does not establish uninterrupted truth between observations, causality,
whole-project health, correctness or independence beyond the governed custody
and topology, deployment identity from repository HEAD, authority to act, or
current support after the qualification occurrence.

## Policy, evidence, and verifier custody

The operator/Pulse-owned `pulse.project-predicate-support-policy/v1` binds:

- project, concern, question, declaration profile, and NQ predicate profile;
- exact NQ catalog, predicate-profile, and input-schema digests;
- accepted primary producer and operator-bound governed subject;
- a distinct signed support producer/key, source, vantage, and exact declared
  dependency closure;
- maximum primary age, support age, and primary/support occurrence skew;
- the exact NQ verifier executable bytes.

The repository concern declaration cannot install this policy. A policy is
JCS/SHA-256 content-bound; changing a predicate/source/currentness rule without
changing the digest is refused.

`pulse.project-predicate-support-evidence/v1` contains bounded facts, exact
observation occurrence, optional producer validity, acquisition/producer/key,
subject, vantage, source, and dependency identities. Its Ed25519 signature
binds the canonical evidence bytes. An opaque `local_state` is retained as
testimony and excluded from the predicate.

Pulse directly invokes the policy-pinned NQ executable with argv (never a
shell), a ten-second runtime bound, bounded output, no stdin, and exact saved
receipt/inventory/catalog. NQ's `bounded-predicate support-evaluate` operation
first replays the original receipt, then evaluates its already-governed profile
over the support facts. Pulse does not parse a claimed `semantic_conclusion`
without this replay and does not duplicate NQ's evaluator.

The expected result is `nq.bounded-predicate-support-evaluation/v1` from the
public native successor. The older `project-predicate` command/schema is not a
fallback. Policy still pins the exact executable; existing policy digests must
be deliberately renewed for new binary bytes. NQ's finite compiled profile and
exclusive300-second maximum can refuse inputs even when a broader Pulse policy
would permit their age. Pulse must not override that refusal or infer compatible
semantics merely from shared field names.

## Independence relation

V1 qualifies topology-relative independence, not metaphysical independence.
The support producer must have a distinct signed identity, and its exact
operator-governed dependency closure may not contain the primary producer,
project status output, Monitor inventory, or NQ receipt. Both paths may observe
the same governed subject. Thus two independent `statvfs` acquisitions of one
filesystem may be eligible, while reading the project's status JSON is not.

The policy binding is a trust root: V1 does not remotely attest that the
producer implementation obeyed its declared source closure. The exact
load-pressure family remains stronger because its producer implementation and
Linux source closure are closed in code.

## Currentness and contradiction

The primary deadline is:

```text
primary observed_at + min(Pulse maximum primary age,
                          producer valid_for_seconds when present)
```

The support deadline is the analogous minimum for the support occurrence.
Both deadlines are exclusive. At equality support is stale. Both occurrences
must precede qualification, and their absolute skew must not exceed the exact
policy bound. The receipt records both occurrences, the qualification
occurrence, skew, and the earlier deadline. Replay uses the original
qualification occurrence and never refreshes time.

The JSON wire uses `i64` for the exclusive Unix-millisecond deadline and
`u64` for skew. Those bounds cover the admitted RFC3339 occurrence domain and
avoid feeding JSON-incompatible 128-bit integer serializers into JCS. A
canonical write/read regression test makes the saved receipt replay seam part
of qualification rather than relying only on in-memory equality.

Dispositions are distinct:

```text
SUPPORTED_CURRENT
NQ_RECEIPT_INVALID
MISSING_SUPPORT
SUPPORT_PRODUCER_FAILED
SUPPORT_EVIDENCE_INVALID
IDENTITY_MISMATCH
INDEPENDENCE_NOT_QUALIFIED
PRIMARY_STALE
SUPPORT_STALE
SKEW_EXCEEDED
CONTRADICTORY
```

Primary true plus support false is `CONTRADICTORY`: current qualified support
is unavailable. It is not a newly admitted negative world claim. Missing,
failed, stale, non-independent, and contradictory support are never merged.

## Operational and replay interface

```sh
pulse-project-predicate-support qualify \
  --policy support-policy.json \
  --nq-executable /qualified/path/nq \
  --nq-receipt admission.json \
  --inventory monitor-inventory.json \
  --catalog predicate-catalog.json \
  --support-evidence signed-support.json \
  --at 2026-08-25T12:01:00Z \
  --output pulse-support.json

pulse-project-predicate-support replay \
  --policy support-policy.json \
  --nq-executable /qualified/path/nq \
  --nq-receipt admission.json \
  --inventory monitor-inventory.json \
  --catalog predicate-catalog.json \
  --support-evidence signed-support.json \
  --receipt pulse-support.json \
  --output replay.json
```

Omitting `--support-evidence` produces `MISSING_SUPPORT`; it does not produce a
semantic false claim. Acquiring raw facts remains the separately administered
support producer's responsibility. Pulse does not execute project-declared
support code.

## Controls and present specimen classification

The Sprocket fixture is absent from Pulse production code. Its primary
`queue.depth <= 17` admission and independently signed support depth 12 produce
`SUPPORTED_CURRENT`; depth 18 produces `CONTRADICTORY`; changing only
`FROBNICATED`, `UNKNOWN`, or another opaque state does not change semantics.

The exact load-pressure family remains the positive control for a closed,
direct Linux producer and arrival-anchored boot-clock receipt. Exact generic
equivalence is deliberately **not** claimed: NQ's current closed predicate
family cannot recompute decimal `/proc/loadavg` parsing and division by logical
CPU count. Accepting a producer-computed normalized value would be weaker than
the narrow contract. The existing family was not changed or deleted.

| Project | Concern | NQ status | Independent support source | Pulse result |
|---|---|---|---|---|
| Weatherwatch | `persistence.access` | admitted family available | none governed | unsupported |
| Weatherwatch | other 9 concerns | no bounded NQ profile | none governed | unsupported |
| Labelwatch | `persistence.sqlite_continuity` | admitted family available | plausible direct SQLite probe, not installed | unsupported |
| Labelwatch | `persistence.volume_capacity` | admitted family available | plausible direct `statvfs`, not installed | unsupported |
| Labelwatch | other 7 concerns | no bounded NQ profile | none governed | unsupported |
| Driftwatch | `persistence.sqlite_continuity` | admitted family available | plausible direct SQLite probe, not installed | unsupported |
| Driftwatch | `persistence.sqlite_slack` | admitted family available | plausible direct SQLite page-count probe, not installed | unsupported |
| Driftwatch | other 7 concerns | no bounded NQ profile | none governed | unsupported |
| Sprocket fixture | `sprocket.queue.bounded` | real NQ admission replayed | separately signed direct-queue fixture source | `SUPPORTED_CURRENT`; contradictory at depth 18 |
| Exact load pressure | `nq.host.load_pressure/v1` | narrow NQ diagnostic contract | existing closed Linux producer | existing narrow support qualified; generic equivalence not expressible |

No fake filesystem, SQLite, Weatherwatch, Labelwatch, or Driftwatch support
producer was added merely to increase this table's supported count.

## Non-goals

This crate does not broaden NQ's predicate language, authenticate arbitrary
project plugins, execute repository support commands, make NQ admissions
mandatory for historical evidence, schedule recurrence, choose severity,
route attention, perform remediation, or emit Nightshift policy. The existing
`nightshift.qualified_support.v1` load-pressure resolver artifact is unchanged;
generic Nightshift attention remains unwired.
