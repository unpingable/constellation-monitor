# NQ host-filesystem-capacity / Pulse correspondence v1

Status: **Candidate**, qualified on one real host through the disposable
same-process profile recorded in the campaign receipts
(`.campaign-artifacts/host-posture-20260924/correspondence-generalization-20260924/REAL-RUN-RESULT.md`,
local). The seam is the qualified load-pressure correspondence
(`nq-host-load-pressure-correspondence-v1.md`) parameterized by question; this
document records only what differs for the filesystem question and what the
parameterization added. The projected component is an operator condition
projection, not a public status component.

## The question row

`pulse-nq-load-correspondence` carries a closed compile-time table
`QuestionV1` (load, filesystem capacity, and since the memory tranche
memory pressure stall). Every persisted carrier (profile, occurrence
preimage, intent, record) names its question through its schema string; a
verifier resolves the string against the table and checks the profile's
constants against the row. Nothing is inferred from payload content, and no
field was added to any carrier: the load row reproduces the load v1 literals
byte for byte, and the load vectors, identity pins and slice 0 sealed profile
are unchanged.

| Field | `HostFilesystemCapacityPressureV1` |
|---|---|
| NQ question | `nq.host_filesystem_capacity.pressure` / `1` / `sha256:a95ea6b0…c81b` |
| NQ profile | `nq.host_filesystem_capacity` / `1` / `sha256:48d23e2e…5636` (detector refusal names version `1`) |
| Claim, condition | `claim:filesystem_capacity_pressure`, `filesystem_capacity_pressure` |
| Subject rule | prefix `host-filesystem:` (NQ's `host-filesystem:<machine-id>/<filesystem-uuid>`); a bare prefix is refused |
| Reliance window, frame validity | `300000 ms`, `298999 ms` (`reliance - fence(1000) - 1`, checked at compile time per row) |
| Pulse scope, coverage tag | `nq.host_filesystem_capacity.pressure/v1`, `nq_host_filesystem_capacity_pressure_v1_terminal_artifact` |
| Acquisition id prefix | `constellation-nq-fs-capacity:v1:` (preimage schema `…correspondence_occurrence.v1`) |
| Transport path, failure domain | `in-process:nq-filesystem-capacity-correspondence/v1`, `domain:nq-filesystem-capacity-correspondence` |
| Schemas | `constellation.nq_host_filesystem_capacity_correspondence_{profile,occurrence,intent}.v1`, record `constellation.nq_host_filesystem_capacity_correspondence.v1` |
| Pulse observation profile | `constellation.nq_host_filesystem_capacity_correspondence` v1, digest domain `….pulse_profile.v1` over `P` |

Shared and fixed across rows: the ingress fence, the frame and ingress
disclosures, the selection rule `nq.deliberate_successor_single_admitted_report`,
the NQ artifact, provenance, refusal and judgment schemas, the record
non-claims, and every verification step of the load contract.

## Consequence

`constellation-status-nq-filesystem-capacity` owns
`constellation.status_consequence.nq_host_filesystem_capacity_pressure.v1`
(fact owner `constellation-status-nq-filesystem-capacity`, pinned
`REQUIRED_QUESTION = HostFilesystemCapacityPressureV1`). The table is the load
table under new reason codes:

| NQ state | Availability | Impact | Projected state | Reason code |
|---|---|---|---|---|
| `present` | `impaired` | `none` | `degraded` | `nq_filesystem_capacity_pressure_present` |
| `explicitly_absent` | `available` | `none` | `healthy` | `nq_filesystem_capacity_pressure_explicitly_absent` |
| `cannot_evaluate` | `indeterminate` | `indeterminate` | `unknown` | `nq_cannot_evaluate` |
| `not_evaluated` | `indeterminate` | `indeterminate` | `unknown` | `nq_not_evaluated` |

Consequence identity (SHA-256 of the canonical table document with its
non-claims): `sha256:5206fd63ee678a4b39c5222af0214c46a5cf125329ebeb70a5370a8c959d3920`.
The non-claims name NQ's qualified capacity threshold without restating it;
the adapter cannot bind the threshold and never reads it.

Label: `Filesystem capacity pressure`. A public policy must use it exactly. An
operator policy may use `Filesystem capacity pressure (<mountpoint>)` where the
mountpoint is an absolute, normalized path with no whitespace or `.`/`..`
segments; the adapter cannot check the mountpoint against the correspondence,
whose subject is the machine id and filesystem UUID, so it is operator-authored
disclosure text (known limit). Reason text, fixed per state:

- healthy: "Qualified filesystem capacity-pressure condition absent in the
  current NQ observation. This is not a storage health or integrity claim."
- degraded: "Qualified filesystem capacity-pressure condition present in the
  current NQ observation. No outage or cause is claimed."
- unknown: "The filesystem capacity-pressure condition is currently unknown.
  This is not an outage."

## Refusals added by the parameterization

- `unsupported_schema`: a profile or record schema outside the table.
- `profile_constant_drift`: a profile whose constants are not its schema's row.
- `invalid_subject`: a subject that does not start with the row's prefix, or is
  the bare prefix (this also newly refuses a bare `host:` load subject).
- `record_question_mismatch`: a record whose schema names another question
  than the verifying profile.
- `artifact_ladder` for a detector `cannot_evaluate` refusal naming another NQ
  profile.
- `certificate_binding_mismatch` on scope; the seam's certificate lookup is by
  consumer, subject and scope.
- Adapters: `question_mismatch` (verified value for another question),
  `selector_mismatch` on scope, `certificate_missing` / `certificate_ambiguous`
  (lookup by consumer, subject and this question's scope; more than one match
  is refused), `public_identity_leak` (a public policy identifier or text
  carrying the machine id or UUID), `condition_contract_mismatch` for an
  operator label carrying either.

## One reactor per question

The qualified shape runs one co-producer and one reactor per question and
subject, with observer and consumer identities distinct per question and
subject. Pulse keys consumers by subject and consumer, so an embedding that
shares a reactor must run `check_disjoint_enrollment` over its profiles first;
sharing is otherwise a convention, not a check.

## Qualification material

- `tests/load_v1_pins.rs`: load row literals, reliance policy and context
  digests, Pulse profile digest, acquisition identity, intent shape, and the
  real slice 0 profile (`sha256:e0fcfc38…d7cd5`) decoding unchanged.
- `tests/question_generalization.rs`: the filesystem profile, frame,
  acquisition identity, ladder, records and co-production; every
  cross-question substitution refused; enrollment overlap refused.
- `artifacts/nq-host-filesystem-capacity-correspondence-v1/`: the load vector
  suite replayed under the filesystem question plus the cross-question and
  foreign-refusal cases, pinned by manifest digest.
- Adapter tests mirror the load adapter's, plus the wrong-question, scope,
  certificate-lookup, public-leak and label-shape refusals.
- Real host: load explicitly absent, `/data` present, UUID substitution and
  machine-identity mismatch refused by NQ and projected unknown; every real
  record refused under the other question or subject.

## Typed owner failure (2026-09-24)

For a detector `cannot_evaluate`, NQ's refusal details may carry the owner's
typed failure code and retriable flag (`failure_code`, `failure_retriable`),
copied by NQ from the helper's single collection error when that code is on
`nq.host_filesystem_capacity`'s closed list (13 codes, defined in the profile
module). The seam parses the two keys strictly into an in-process
`OwnerFailureV1 {code, retriable: Option<bool>}` on the verified value, only
for a refusal already pinned to this row. The parsed value is not a record
field and never enters a frame; the record embeds NQ's artifact exactly as
NQ wrote it, which already carries the two detail keys, and the record
schema did not change. The state never changes. The seam's only rule on a
code is its shape: a lowercase token (`[a-z][a-z0-9_]*`, at most 64 bytes),
which every owner's list satisfies. The adapter's
`operator_explanation()` maps six of those codes to bounded operator text
(no path, identity, or helper prose); the fact, the consequence table and
identity, and the rendered text are unchanged, so unknown stays unknown. A
mutated key fails the artifact identity; a malformed value or an unlisted
code yields no explanation. An operator policy that discloses
`ComponentOutputFieldV1::Detail` may carry that explanation as the
component's `detail`: an optional bounded display-only text
(`ComponentDetailV1`, attached to the component's one fact by
`operator_detail()`) that the projector copies and never reads. It is absent
by default, refused for a public policy, excluded from the basis digest, and
takes no part in any evaluation, window or state; the projection decision is
identical with or without it. The unavailable page then lists the condition,
its unavailable state and `Detail: …`, and still states no conclusion.
