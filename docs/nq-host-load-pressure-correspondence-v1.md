# NQ host-load-pressure / Pulse correspondence v1

Status: **Qualified** for the bounded disposable, same-process profile
recorded in the
qualification receipt (historical evidence retained outside this public source cut).
The local implementation and synthetic fixtures did not replace the real
disposable NQ run or the independent review; both were completed and accepted
as that receipt records. Standing was Candidate until that acceptance. The
projected component is an operator condition projection, not a public status
component (see `status-projection-v1.md`, "Positioning").

## Ownership and claim boundary

NQ remains the sole owner of its native `nq.host.load_pressure/v1` judgment.
Pulse remains the sole owner of current support for an exact Pulse frame. The
`pulse-nq-load-correspondence` leaf crate owns only the deliberate pairing of
one NQ local-successor acquisition with one Pulse frame sealed before that
acquisition. The independent `pulse-nq-load-support` family is neither used nor
changed.

The `constellation-status-nq-load-pressure` leaf crate owns the narrow
projection consequence contract
`constellation.status_consequence.nq_host_load_pressure.v1`. The generic
projector remains unchanged. The projected component represents only the
load-pressure condition:

| NQ state | Availability | Impact | Projected state |
|---|---|---|---|
| `present` | `impaired` | `none` | `degraded` |
| `explicitly_absent` | `available` | `none` | `healthy` |
| `cannot_evaluate` | `indeterminate` | `indeterminate` | `unknown` |
| `not_evaluated` | `indeterminate` | `indeterminate` | `unknown` |

Here `degraded` is this projection policy's display of an NQ warning-level
condition; it claims no impairment, outage, impact, or cause. `healthy` means
only that the qualified bounded condition was explicitly absent with complete
current local coverage. It establishes no general host or service health,
reachability, capacity, or cause. `unknown` is not an outage. The mapping
grants no authority.

Presentation: `healthy` is the projector's closed axis vocabulary (available
and no impact) and appears only in the artifact's machine-readable `state`
fields. The renderer labels that state `No issue reported` and appends the
condition reason with its non-claim, so the operator reads
`Host load-pressure condition: No issue reported — Qualified load-pressure
condition absent … This is not a host or service health claim.` No audience is
shown "Healthy" or "Operational"; `tests/presentation.rs` pins this.

## One co-produced occurrence

The co-producer and Pulse reactor operate in one process. At process start the
embedding supplies the enrolled subject incarnation, and the co-producer
creates a fresh random observer incarnation and a process-local monotonic
origin. For each finite occurrence it:

1. rechecks that the subject incarnation is unchanged;
2. seals an empty-signal Pulse frame with exact terminal-artifact coverage and
   validity `298999 ms`;
3. derives the Pulse evidence reference, then derives the caller-named NQ
   acquisition ID from that reference, the enrolled NQ instance, and the
   correspondence profile digest;
4. writes a create-new intent before invoking NQ;
5. invokes only `acquire-next-local`, `replay-local-successor`, and `qualify`
   through a bounded, cleared-environment, null-stdin, digest-pinned port; the
   port trait is sealed, and its complete enrollment must exactly match the
   correspondence profile before custody paths are created, so downstream
   code cannot substitute another enrolled command carrier while retaining the
   verified correspondence type;
6. requires a canonical pinned NQ v2 artifact, byte-identical replay, and
   matching NQ admission provenance;
7. submits the exact frame to the in-process reactor with its measured holding
   delay; and
8. writes a canonical create-new audit record.

A failure before delivery burns the sequence and delivers no frame. Reusing an
acquisition ID is refused. Restart creates a new observer incarnation; Pulse
decides the restarted stream's standing. Resubmitting an identical frame does
not move its evidence expiry.

If the acquire command was launched but its result is lost, the same live
co-producer performs exactly one read-only `replay-local-successor` for the
already precommitted acquisition ID. An exact result then follows the ordinary
artifact checks and the ordinary second byte-equality replay. A pin/read error
or `nq_spawn` is known to precede launch and is not replayed. An absent or
refused reconciliation burns the occurrence with both disposition codes and
never issues another acquisition. This is same-process result reconciliation,
not restart recovery: no frame or monotonic timing anchor is reconstructed
after process loss.

## Time composition and custody

NQ's source reliance window is `300000 ms`. The maximum ingress fence is
`1000 ms`, and Pulse frame validity is `300000 - 1000 - 1 = 298999 ms`.
Holding delay is rounded up and must be strictly below frame validity. The
reactor-return fence is rounded up and must be at most `1000 ms`. Pulse
subtracts holding delay, and the live-query anchor plus projector may only
shorten the remaining interval. No absolute monotonic tick crosses the process
boundary.

The canonical `constellation.nq_host_load_pressure_correspondence.v1` record
contains the exact Pulse wire bytes, evidence reference, NQ artifact and
admission provenance, derived NQ state, measured delivery durations, fixed
non-claims, and `mutation_authority: "none"`. Its content identity is SHA-256
over RFC 8785 canonical JSON with `correspondence_id` omitted.

That record is historical audit evidence only. Audit verification cannot
recreate currentness. Only the non-cloneable, non-serializable
`VerifiedCorrespondenceV1` built during the live co-production sequence can be
offered to the consequence adapter. The adapter additionally requires a fresh
live query whose current certificate lists exactly the paired evidence
reference and subject incarnation.

For every audience, that adapter also requires the qualified
load-pressure-condition label, the reason field, and the exact safe reason
table that carries the condition's non-claims, and it refuses any hard or soft
dependency edge that names the condition component as parent or dependency.
Relabeling it as general host health, omitting those non-claims, or routing
another component's state through it is refused by `fact_for` and by
`admit_live`; the generic projector remains policy-generic. An embedding that
builds facts by hand bypasses this guard; the adapter's tests record that as a
known limit.

## Qualification material

Canonical audit-verifier vectors and a digest-pinned mirror of NQ's v2
contract fixtures live in
[`artifacts/nq-host-load-pressure-correspondence-v1/`](../artifacts/nq-host-load-pressure-correspondence-v1/README.md).
Synthetic vectors exercise the closed verifier but are not NQ output and do
not establish a positive deployment claim. Focused tests exercise a real local
Pulse reactor, lifetime boundaries, sequence gaps, restart and duplicate
behavior, live-query admission, disclosure reduction, dependencies, and local
atomic publication.

Qualification required a disposable environment supplying a profile enrolled
from NQ commit `6190218f1da817d6900d1dbc551d52818673154e`, a schema-13 store
with the required prior watcher history, an executable not writable by the
embedding principal, fresh custody paths, real Present and ExplicitlyAbsent
occurrences, and an independent frozen review. The receipt records that run.
The ignored real-run harnesses do not themselves grant acceptance. A changed
profile, NQ commit, table, non-claim, or schema needs a new run; a tightening
that only adds refusals, such as the 2026-09-24 guard extension, does not.

## Disposable real-NQ procedure

The smallest deterministic provider is NQ's own host-diagnostic test pattern.
The Monitor copy is
[`nq_host_diagnostic_helper.py`](../crates/pulse-nq-load-correspondence/tests/fixtures/nq_host_diagnostic_helper.py),
with its configuration template beside it. `complete` reports four CPUs and a
one-minute load of 1.0, so NQ decides `explicitly_absent`; `present` changes
only that fixture value to 12.0, so NQ decides `present` under its compiled
2.0 normalized-load threshold; `partial` is NQ's existing incomplete-load
case and produces its detector-origin `cannot_evaluate`. These are local
substitution fixtures, not production host data. The mutable mode file is not
an NQ identity: the admitted Python helper, command, binding, profile, and
configuration remain unchanged.

Use an otherwise empty qualification root. Build commit
`6190218f1da817d6900d1dbc551d52818673154e` with debug assertions (the fixture
uses NQ's debug-only same-identity exception), then install the resulting `nq`
binary and rendered configuration under root-owned, non-writable paths. Render
the template's `@ROOT@` as the qualification root and `@EXECUTION_UID@` as the
qualification principal's numeric UID. Copy the Python fixture to the exact
`@ROOT@` path, create `mode` containing `complete`, and run, as that principal:

```sh
/absolute/root-owned/nq --config /absolute/root-owned/nq.toml config check
/absolute/root-owned/nq --config /absolute/root-owned/nq.toml init
/absolute/root-owned/nq --config /absolute/root-owned/nq.toml \
  watcher admit host-diagnostic.primary
/absolute/root-owned/nq --config /absolute/root-owned/nq.toml \
  diagnostics execute host-diagnostic.primary > /absolute/root/initial.json
artifact=$(jq -er .artifact_id /absolute/root/initial.json)
/absolute/root-owned/nq --config /absolute/root-owned/nq.toml --json \
  diagnostics qualify "$artifact" > /absolute/root/initial.provenance.json
/absolute/root-owned/nq --config /absolute/root-owned/nq.toml \
  diagnostics export "$artifact" > /absolute/root/initial.export.json
cmp /absolute/root/initial.json /absolute/root/initial.export.json
```

This establishes the required initial state: one fresh schema-13 store and
genesis, one active admission for `host-diagnostic.primary`, and exactly one
matching ordinary diagnostic history occurrence. Do not initialize another
store or repeat `diagnostics execute`; every correspondence occurrence after
this point uses NQ's local-successor path.

Seal the correspondence profile from `initial.json`; the helper refuses a
different compiled question/profile and copies the artifact's runtime-derived
subject, scope, vantage, profile semantic ID, threshold policy, evaluator,
state model, producer node/build/cohort, plus hashes of the exact executable
and configuration. The four Pulse identities are explicit deployment
enrollment, not NQ-derived values:

```sh
NQ_CORRESPONDENCE_INITIAL_ARTIFACT=/absolute/root/initial.json \
NQ_CORRESPONDENCE_NQ_EXECUTABLE=/absolute/root-owned/nq \
NQ_CORRESPONDENCE_NQ_CONFIG=/absolute/root-owned/nq.toml \
NQ_CORRESPONDENCE_PROFILE_OUT=/absolute/root/profile.json \
NQ_CORRESPONDENCE_INSTANCE_ID=host-diagnostic.primary \
NQ_CORRESPONDENCE_OBSERVER_ID=observer:nq-load-correspondence:disposable-v1 \
NQ_CORRESPONDENCE_CONSUMER_ID=consumer:status-projection-nq-load:disposable-v1 \
NQ_CORRESPONDENCE_POLICY_GENERATION=policy:nq-load-correspondence:disposable-v1 \
NQ_CORRESPONDENCE_OBSERVATION_POLICY_GENERATION=observation-policy:nq-load-correspondence:disposable-v1 \
cargo run -p pulse-nq-load-correspondence --example seal_real_profile
```

For each of `present`, `complete`, and `partial`, write only that word to the
mode file and invoke the projection harness once with a fresh custody root and
fresh publication root. Map `complete` to the required harness expectation
`explicitly_absent`:

```sh
NQ_CORRESPONDENCE_PROFILE=/absolute/root/profile.json \
NQ_CORRESPONDENCE_CUSTODY_ROOT=/absolute/root/runs/present/custody \
NQ_CORRESPONDENCE_PUBLISH_ROOT=/absolute/root/runs/present/publish \
NQ_CORRESPONDENCE_EXPECTED_STATE=present \
NQ_CORRESPONDENCE_OCCURRENCES=1 \
cargo test -p constellation-status-nq-load-pressure \
  --test real_projection real_projection_chain -- --exact --ignored --nocapture
```

The other expected pairs are `complete` / `explicitly_absent` and `partial` /
`cannot_evaluate`. The harness now fails on an acquisition refusal, audit-only
result, wrong NQ state, wrong projected state, verification failure, or
publication failure. Each successful run retains a create-new intent, exact
audit record, Pulse journal, and independent public and operator publications
below `public/` and `operator/`. The public artifact has no basis digest; the
operator artifact has its independently computed basis digest. Each
publication has its own immutable object and `CURRENT` pointer. Capture
stdout/stderr and terminal exit in the campaign's durable user unit; those
files and the NQ store are qualification evidence. A retained audit record or
projected object does not independently prove acquisition linkage or recreate
live support; that proof exists only during the successful co-production
process.
