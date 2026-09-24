# Deterministic status projection v1

Status projection is an experimental, read-only boundary for turning exact,
versioned Constellation records into a small audience-specific snapshot. It is
not a monitor, scheduler, database, health service, incident system, or source
of authority.

The `constellation-status-projection` leaf crate owns only:

- a closed projection-policy schema;
- normalized availability, impact, freshness, and maintenance axes;
- explicit projection-local dependency behavior;
- disclosure reduction before rendering;
- a canonical status-artifact schema and SHA-256 identity;
- a reduced-input renderer; and
- a local, single-publisher atomic publication helper.

Monitor, Pulse, NQ, Nightshift, Standing, and other producers keep ownership of
their native facts. The projector never feeds its result back into them.

## Freshness boundary

A positive state requires both a state-bearing observed or admitted fact and a
fresh `pulse.live_present_support_response.v1` result for the exact supporting
evidence. `LiveQueryAnchorV1::begin` is created before sending the request and
is consumed once by `admit` after response decoding. Admission validates the
exact request, response, certificate, qualified generation, evidence identity,
and receiver lineage, then subtracts the complete process-local elapsed time
from Pulse's source-owned remaining duration.

The in-memory observation is deliberately not serializable. Possessing or
replaying a response does not reconstruct present support. A fresh result must
come from a fresh query. The non-cloneable anchor measures request transit,
source processing, response transit, decoding, and admission delay; the
in-memory observation's remaining duration continues to decrease afterward.
The projector applies the shortest relevant remaining interval, its static
maximum age, and its admitted presentation-clock uncertainty. It never compares
monotonic clocks across processes and never invents a wall-clock meaning for a
Pulse receiver tick. Correct embedding still requires creating the anchor before
transmission; the type cannot prove that an external transport was actually used.

`fresh_until_unix_ms` is a conservative presentation deadline on the caller's
declared timeline. It is not a Pulse receiver deadline or a durable freshness
claim. At or after that deadline the renderer displays `Status unavailable` and
does not show the retained component states.

Pulse `CURRENT`, an NQ snapshot, qualification, Standing, process success, or
an operator maintenance assertion is individually insufficient to produce
`healthy`. Missing, expired, contradictory, or unsupported required evidence
produces `unknown`; observer unavailability is not called a service outage.

## Inputs and current adapters

The spike admits:

- synthetic normalized facts whose class is explicitly `observed` or
  `derived_admitted`, with owner, native schema, and exact Pulse selector pinned
  by policy;
- exact Pulse live-present-support exchanges, which supply bounded present
  support but no health conclusion; and
- bounded maintenance annotations, which change only the displayed mode.

No current product export is admitted as a real state adapter. In particular,
`nq.status_snapshot.v3` is a coarse operator-compatibility view: its `healthy`
state may represent either an observed condition being present or explicitly
absent, and it is not bound to the Pulse evidence identity used here. Treating
that view as a normalized availability fact would invent meaning, so the
earlier proposed NQ adapter was removed.

### Candidate NQ load-pressure consequence adapter

The leaf `constellation-status-nq-load-pressure` crate is a Candidate adapter
for one deliberately co-produced relationship defined by
[`nq-host-load-pressure-correspondence-v1.md`](nq-host-load-pressure-correspondence-v1.md).
It does not admit `nq.status_snapshot.v3`, a retained correspondence record, or
the independent `pulse-nq-load-support` family. It accepts only the
non-serializable `VerifiedCorrespondenceV1` created during the same-process NQ
acquire/replay/qualify and Pulse-ingress sequence, plus a fresh live query for
the exact paired evidence reference.

The adapter owns only
`constellation.status_consequence.nq_host_load_pressure.v1`. Present maps to
`impaired/none` and the condition component displays `degraded`; explicitly
absent maps to `available/none` and that condition component displays
`healthy`. Cannot-evaluate, other unevaluated outcomes, stale support, and any
mismatch map to `unknown`. A structural guard requires the component to have
exactly this one fact. These are condition-specific projection consequences,
not NQ claims about general host or service health. Candidate standing remains
until the real disposable run and independent frozen review succeed.

There are no v1 adapters for Nightshift, Standing, AG, Phosphor, or free-form
Monitor project-concern records. Their historical records must not be
reinterpreted as present health.

The current Pulse API confirms whether an exact supplied support certificate is
still current; it does not discover the latest certificate for a subject. A
separate-process deployment therefore still needs an embedding-owned,
qualified way to select the exact certificate before making the live query.
It also needs a source-owned state export whose semantic result and basis are
bound to that selected support evidence. Those deployment connections are
outside this local spike and block a real disposable off-host projection.

## Dependency and disclosure rules

Policies contain only explicit `all_of` dependency edges. Each hard or soft
edge declares its behavior for unavailable, degraded, and unknown dependencies.
Informational edges cannot alter state or freshness. There is no implicit
"worst child wins", quorum, weight, score, or expression language.

Public reduction happens before rendering. A public artifact contains only
projection-local identifiers, explicitly selected fields, and allowlisted
reason text. It contains no source identifiers, repository or host names,
dependency graph, hidden component count, receipt details, provenance records,
or arbitrary producer/operator text. Operator policies may include more
components and an opaque basis digest, but are evaluated independently rather
than derived as a debug superset of a public artifact.

The checked-in `public-atproto` and `neutral-zone-operator` policies are
synthetic conformance fixtures. Their names demonstrate two independently
reduced audiences; they are not deployed inventory or production bindings.

## Local publication and rendering

The publication helper writes a canonical immutable object, synchronizes and
revalidates it, stages a canonical current pointer, and replaces `CURRENT`
atomically only on commit. A failed or interrupted stage leaves the prior
complete pointer in place. It refuses cross-projection replacement and a
replacement older than the current generation time. The helper assumes one coordinated local publisher;
it does not provide distributed locking, retention, remote storage, or cleanup.

The SHA-256 artifact identifier detects content mismatch; it does not
authenticate a publisher. Publisher identity and remote storage credentials are
deployment concerns, not claims made by this spike.

The `constellation-status` CLI validates, renders, locally publishes, and reads
already reduced artifacts. It intentionally has no offline `project` command:
a retained response file plus a caller-supplied zero elapsed time would not be
a trustworthy live query. Live projection is an embedding API until a bounded
client performs the query and elapsed-time measurement in one operation.

```sh
cargo run -p constellation-status-projection --bin constellation-status -- validate ARTIFACT
cargo run -p constellation-status-projection --bin constellation-status -- render ARTIFACT NOW_UNIX_MS UNCERTAINTY_MS
cargo run -p constellation-status-projection --bin constellation-status -- publish LOCAL_ROOT ARTIFACT
cargo run -p constellation-status-projection --bin constellation-status -- read-current LOCAL_ROOT
```

## Deliberately unsupported

- production or off-host publication;
- remote evidence transport;
- a qualified real state-source adapter;
- certificate discovery;
- concurrent publishers;
- status history, incidents, paging, alerts, or notification delivery;
- any acquisition, authorization, mutation, or control interface;
- arbitrary rules, quorum, scoring, or audience-specific logic in the generic
  crate.

The local spike proves the deterministic semantic and filesystem boundaries.
It does not qualify a deployed status page or an off-host clock/publication
path.
